package com.example.security.service;

import com.example.security.model.SecurityLog;
import org.springframework.stereotype.Service;
import ml.dmlc.xgboost4j.java.Booster;
import ml.dmlc.xgboost4j.java.DMatrix;
import ml.dmlc.xgboost4j.java.XGBoost;
import weka.classifiers.Evaluation;
import weka.classifiers.Classifier;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.Logistic;
import weka.classifiers.meta.Vote;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SelectedTag;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Collections;

@Service
public class MlRandomForestService {
    private static final String[] FEATURE_NAMES = new String[]{
            "method_is_get",
            "method_is_post",
            "path_len",
            "special_char_count",
            "digit_count",
            "has_sql_keywords",
            "has_xss_keywords",
            "has_traversal",
            "ua_len",
            "ua_is_empty"
    };

    private volatile Classifier model;
    private volatile Booster xgbModel;
    private volatile Instances header;
    private volatile boolean trained;
    private volatile int trainedSamples;
    private volatile String trainedAt;
    private volatile double lastHoldoutAccuracy;
    private volatile String modelType;

    public synchronized TrainResult train(List<SecurityLog> logs) throws Exception {
        return train(logs, "RANDOM_FOREST");
    }

    public synchronized TrainResult train(List<SecurityLog> logs, String requestedModelType) throws Exception {
        String type = normalizeModelType(requestedModelType);
        if (logs == null || logs.size() < 30) {
            this.trained = false;
            this.trainedSamples = logs == null ? 0 : logs.size();
            this.trainedAt = null;
            this.lastHoldoutAccuracy = 0.0;
            this.modelType = type;
            this.model = null;
            this.xgbModel = null;
            this.header = null;
            return new TrainResult(false, this.trainedSamples, 0.0);
        }

        List<SecurityLog> sorted = new ArrayList<>(logs);
        sorted.sort(Comparator.comparing(SecurityLog::getTimestamp, Comparator.nullsLast(Comparator.naturalOrder())));

        int split = Math.max((int) Math.floor(sorted.size() * 0.8), 1);
        List<SecurityLog> trainLogs = sorted.subList(0, split);
        List<SecurityLog> testLogs = sorted.subList(split, sorted.size());

        Instances train = buildDataset(trainLogs);
        Instances test = buildDataset(testLogs);

        double acc;
        if ("XGBOOST".equals(type)) {
            Booster booster = trainXgboost(train, test);
            this.model = null;
            this.xgbModel = booster;
            this.header = new Instances(train, 0);
            acc = evaluateXgboost(booster, test);
        } else if ("HYBRID".equals(type)) {
            Classifier weka = buildClassifier("ENSEMBLE", train);
            Booster booster = trainXgboost(train, test);
            this.model = weka;
            this.xgbModel = booster;
            this.header = new Instances(train, 0);
            acc = evaluateHybrid(weka, booster, test);
        } else {
            Classifier clf = buildClassifier(type, train);
            this.model = clf;
            this.xgbModel = null;
            this.header = new Instances(train, 0);
            acc = evaluateWeka(clf, train, test);
        }

        this.trained = true;
        this.trainedSamples = sorted.size();
        this.trainedAt = LocalDateTime.now().toString();
        this.lastHoldoutAccuracy = acc;
        this.modelType = type;

        return new TrainResult(true, this.trainedSamples, acc);
    }

    public Prediction predict(SecurityLog log) {
        Classifier rf = this.model;
        Booster xgb = this.xgbModel;
        Instances hdr = this.header;
        if (!trained || hdr == null || log == null) {
            return new Prediction(false, 0.0);
        }
        try {
            float[] features = toFeatures(log);
            double prob;
            if ("XGBOOST".equals(modelType) && xgb != null) {
                prob = predictXgboost(xgb, features);
            } else if ("HYBRID".equals(modelType) && xgb != null && rf != null) {
                Instance inst = toInstanceWithFeatures(features, log, hdr);
                double wekaProb = predictWeka(rf, inst);
                double xgbProb = predictXgboost(xgb, features);
                prob = (wekaProb + xgbProb) / 2.0;
            } else if (rf != null) {
                Instance inst = toInstanceWithFeatures(features, log, hdr);
                prob = predictWeka(rf, inst);
            } else {
                return new Prediction(false, 0.0);
            }
            boolean predicted = prob >= 0.5;
            return new Prediction(predicted, clamp01(prob));
        } catch (Exception e) {
            return new Prediction(false, 0.0);
        }
    }

    public Explanation explain(SecurityLog log, int topK) {
        Booster xgb = this.xgbModel;
        Classifier weka = this.model;
        Instances hdr = this.header;
        if (!trained || log == null || xgb == null) {
            return null;
        }
        if (!"XGBOOST".equals(modelType) && !"HYBRID".equals(modelType)) {
            return null;
        }
        try {
            float[] features = toFeatures(log);
            DMatrix mat = new DMatrix(features, 1, features.length, Float.NaN);
            float[] contribRow = shapContribs(xgb, mat);
            double baseValue = contribRow.length > features.length ? contribRow[features.length] : 0.0;
            List<ShapContribution> contribs = new ArrayList<>();
            for (int i = 0; i < features.length && i < FEATURE_NAMES.length && i < contribRow.length; i++) {
                contribs.add(new ShapContribution(FEATURE_NAMES[i], features[i], contribRow[i]));
            }
            contribs.sort((a, b) -> Double.compare(Math.abs(b.contribution), Math.abs(a.contribution)));
            int take = Math.min(Math.max(topK, 1), contribs.size());
            List<ShapContribution> top = new ArrayList<>(contribs.subList(0, take));

            double xgbProb = predictXgboost(xgb, features);
            Double wekaProb = null;
            Double combinedProb = null;
            if ("HYBRID".equals(modelType) && weka != null && hdr != null) {
                Instance inst = toInstanceWithFeatures(features, log, hdr);
                wekaProb = predictWeka(weka, inst);
                combinedProb = (wekaProb + xgbProb) / 2.0;
            }

            return new Explanation(modelType, xgbProb, wekaProb, combinedProb, baseValue, top);
        } catch (Exception e) {
            return null;
        }
    }

    public Status status() {
        return new Status(trained, trainedSamples, trainedAt, lastHoldoutAccuracy, modelType);
    }

    private Classifier buildClassifier(String type, Instances train) throws Exception {
        if ("ENSEMBLE".equals(type)) {
            RandomForest rf = new RandomForest();
            rf.setNumIterations(80);
            rf.setSeed(7);

            J48 tree = new J48();
            NaiveBayes nb = new NaiveBayes();
            Logistic log = new Logistic();

            Vote ensemble = new Vote();
            ensemble.setClassifiers(new Classifier[]{rf, tree, nb, log});
            ensemble.setCombinationRule(new SelectedTag(Vote.AVERAGE_RULE, Vote.TAGS_RULES));
            ensemble.buildClassifier(train);
            return ensemble;
        }

        RandomForest rf = new RandomForest();
        rf.setNumIterations(120);
        rf.setSeed(7);
        rf.buildClassifier(train);
        return rf;
    }

    private double evaluateWeka(Classifier clf, Instances train, Instances test) throws Exception {
        if (test.numInstances() <= 0) return 0.0;
        Evaluation eval = new Evaluation(train);
        eval.evaluateModel(clf, test);
        return eval.pctCorrect() / 100.0;
    }

    private double predictWeka(Classifier clf, Instance inst) throws Exception {
        double[] dist = clf.distributionForInstance(inst);
        return dist.length > 1 ? dist[1] : 0.0;
    }

    private Booster trainXgboost(Instances train, Instances test) throws Exception {
        int featureCount = train.numAttributes() - 1;
        DMatrix trainMat = toXgbMatrix(train, featureCount);
        DMatrix testMat = test.numInstances() > 0 ? toXgbMatrix(test, featureCount) : null;

        Map<String, Object> params = new HashMap<>();
        params.put("eta", 0.2);
        params.put("max_depth", 6);
        params.put("subsample", 0.9);
        params.put("colsample_bytree", 0.9);
        params.put("objective", "binary:logistic");
        params.put("eval_metric", "logloss");
        params.put("seed", 7);

        Map<String, DMatrix> watches = new HashMap<>();
        watches.put("train", trainMat);
        if (testMat != null) watches.put("test", testMat);

        return XGBoost.train(trainMat, params, 120, watches, null, null);
    }

    private double evaluateXgboost(Booster booster, Instances test) throws Exception {
        if (test.numInstances() <= 0) return 0.0;
        int featureCount = test.numAttributes() - 1;
        float[] data = new float[test.numInstances() * featureCount];
        int idx = 0;
        for (int i = 0; i < test.numInstances(); i++) {
            Instance inst = test.instance(i);
            for (int j = 0; j < featureCount; j++) {
                data[idx++] = (float) inst.value(j);
            }
        }
        DMatrix mat = new DMatrix(data, test.numInstances(), featureCount, Float.NaN);
        float[][] preds = booster.predict(mat);
        int correct = 0;
        for (int i = 0; i < test.numInstances(); i++) {
            double prob = preds[i][0];
            int pred = prob >= 0.5 ? 1 : 0;
            int actual = (int) test.instance(i).classValue();
            if (pred == actual) correct++;
        }
        return test.numInstances() == 0 ? 0.0 : (double) correct / (double) test.numInstances();
    }

    private double evaluateHybrid(Classifier weka, Booster booster, Instances test) throws Exception {
        if (test.numInstances() <= 0) return 0.0;
        int featureCount = test.numAttributes() - 1;
        float[] data = new float[test.numInstances() * featureCount];
        int idx = 0;
        for (int i = 0; i < test.numInstances(); i++) {
            Instance inst = test.instance(i);
            for (int j = 0; j < featureCount; j++) {
                data[idx++] = (float) inst.value(j);
            }
        }
        DMatrix mat = new DMatrix(data, test.numInstances(), featureCount, Float.NaN);
        float[][] xgbPreds = booster.predict(mat);
        int correct = 0;
        for (int i = 0; i < test.numInstances(); i++) {
            Instance inst = test.instance(i);
            double wekaProb = predictWeka(weka, inst);
            double xgbProb = xgbPreds[i][0];
            double prob = (wekaProb + xgbProb) / 2.0;
            int pred = prob >= 0.5 ? 1 : 0;
            int actual = (int) inst.classValue();
            if (pred == actual) correct++;
        }
        return (double) correct / (double) test.numInstances();
    }

    private double predictXgboost(Booster booster, float[] features) throws Exception {
        DMatrix mat = new DMatrix(features, 1, features.length, Float.NaN);
        float[][] preds = booster.predict(mat);
        return preds.length > 0 && preds[0].length > 0 ? preds[0][0] : 0.0;
    }

    private float[] shapContribs(Booster booster, DMatrix mat) throws Exception {
        try {
            try {
                java.lang.reflect.Method m6 = booster.getClass().getMethod(
                        "predict",
                        DMatrix.class,
                        boolean.class,
                        int.class,
                        boolean.class,
                        boolean.class,
                        boolean.class
                );
                float[][] out = (float[][]) m6.invoke(booster, mat, false, 0, false, true, false);
                return out != null && out.length > 0 ? out[0] : new float[0];
            } catch (NoSuchMethodException e) {
                java.lang.reflect.Method m5 = booster.getClass().getMethod(
                        "predict",
                        DMatrix.class,
                        boolean.class,
                        int.class,
                        boolean.class,
                        boolean.class
                );
                float[][] out = (float[][]) m5.invoke(booster, mat, false, 0, false, true);
                return out != null && out.length > 0 ? out[0] : new float[0];
            }
        } catch (Exception e) {
            float[][] out = booster.predict(mat);
            return out != null && out.length > 0 ? out[0] : new float[0];
        }
    }

    private DMatrix toXgbMatrix(Instances data, int featureCount) throws Exception {
        float[] flat = new float[data.numInstances() * featureCount];
        float[] labels = new float[data.numInstances()];
        int idx = 0;
        for (int i = 0; i < data.numInstances(); i++) {
            Instance inst = data.instance(i);
            for (int j = 0; j < featureCount; j++) {
                flat[idx++] = (float) inst.value(j);
            }
            labels[i] = (float) inst.classValue();
        }
        DMatrix mat = new DMatrix(flat, data.numInstances(), featureCount, Float.NaN);
        mat.setLabel(labels);
        return mat;
    }

    private String normalizeModelType(String value) {
        if (value == null) return "RANDOM_FOREST";
        String v = value.trim().toUpperCase();
        if ("ENSEMBLE".equals(v)) return "ENSEMBLE";
        if ("VOTE".equals(v)) return "ENSEMBLE";
        if ("XGBOOST".equals(v)) return "XGBOOST";
        if ("XGB".equals(v)) return "XGBOOST";
        if ("HYBRID".equals(v)) return "HYBRID";
        if ("RF_XGB".equals(v)) return "HYBRID";
        if ("RANDOMFOREST".equals(v)) return "RANDOM_FOREST";
        if ("RANDOM_FOREST".equals(v)) return "RANDOM_FOREST";
        if ("RF".equals(v)) return "RANDOM_FOREST";
        return "RANDOM_FOREST";
    }

    private Instances buildDataset(List<SecurityLog> logs) {
        ArrayList<Attribute> attrs = new ArrayList<>();
        attrs.add(new Attribute("method_is_get"));
        attrs.add(new Attribute("method_is_post"));
        attrs.add(new Attribute("path_len"));
        attrs.add(new Attribute("special_char_count"));
        attrs.add(new Attribute("digit_count"));
        attrs.add(new Attribute("has_sql_keywords"));
        attrs.add(new Attribute("has_xss_keywords"));
        attrs.add(new Attribute("has_traversal"));
        attrs.add(new Attribute("ua_len"));
        attrs.add(new Attribute("ua_is_empty"));

        ArrayList<String> classVals = new ArrayList<>();
        classVals.add("0");
        classVals.add("1");
        attrs.add(new Attribute("intrusion", classVals));

        Instances data = new Instances("intrusion_data", attrs, Math.max(logs.size(), 1));
        data.setClassIndex(data.numAttributes() - 1);

        for (SecurityLog log : logs) {
            Instance inst = toInstance(log, data);
            data.add(inst);
        }
        return data;
    }

    private Instance toInstance(SecurityLog log, Instances datasetOrHeader) {
        float[] features = toFeatures(log);
        return toInstanceWithFeatures(features, log, datasetOrHeader);
    }

    private Instance toInstanceWithFeatures(float[] features, SecurityLog log, Instances datasetOrHeader) {
        double[] vals = new double[datasetOrHeader.numAttributes()];
        for (int i = 0; i < 10; i++) {
            vals[i] = features[i];
        }
        boolean intrusion = isIntrusionLabel(log);
        vals[10] = intrusion ? 1.0 : 0.0;
        DenseInstance inst = new DenseInstance(1.0, vals);
        inst.setDataset(datasetOrHeader);
        return inst;
    }

    private float[] toFeatures(SecurityLog log) {
        float[] f = new float[10];
        String method = log.getRequestMethod() == null ? "" : log.getRequestMethod().toUpperCase();
        f[0] = "GET".equals(method) ? 1.0f : 0.0f;
        f[1] = "POST".equals(method) ? 1.0f : 0.0f;

        String path = log.getRequestPath() == null ? "" : log.getRequestPath();
        String p = path.toLowerCase();
        f[2] = (float) Math.min(path.length(), 4096);
        f[3] = (float) countSpecial(p);
        f[4] = (float) countDigits(p);
        f[5] = hasSql(p) ? 1.0f : 0.0f;
        f[6] = hasXss(p) ? 1.0f : 0.0f;
        f[7] = hasTraversal(p) ? 1.0f : 0.0f;

        String ua = log.getUserAgent() == null ? "" : log.getUserAgent();
        f[8] = (float) Math.min(ua.length(), 2048);
        f[9] = ua.isBlank() ? 1.0f : 0.0f;
        return f;
    }

    private boolean isIntrusionLabel(SecurityLog log) {
        if (log.isSuspicious()) return true;
        String status = log.getStatus();
        if (status == null) return false;
        return !"NORMAL".equalsIgnoreCase(status);
    }

    private int countSpecial(String s) {
        int c = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\'' || ch == '"' || ch == '<' || ch == '>' || ch == ';' || ch == '%' || ch == '=' || ch == '-' || ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == '[' || ch == ']' || ch == '\\' || ch == '/') {
                c++;
            }
        }
        return Math.min(c, 999);
    }

    private int countDigits(String s) {
        int c = 0;
        for (int i = 0; i < s.length(); i++) {
            if (Character.isDigit(s.charAt(i))) c++;
        }
        return Math.min(c, 999);
    }

    private boolean hasSql(String s) {
        return s.contains("union select") || s.contains("or 1=1") || s.contains("drop table") || s.contains("information_schema") || s.contains("'--") || s.contains("\"--");
    }

    private boolean hasXss(String s) {
        return s.contains("<script") || s.contains("javascript:") || s.contains("onerror=") || s.contains("onload=") || s.contains("%3cscript");
    }

    private boolean hasTraversal(String s) {
        return s.contains("../") || s.contains("..\\") || s.contains("%2e%2e");
    }

    private double clamp01(double v) {
        if (v < 0.0) return 0.0;
        if (v > 1.0) return 1.0;
        return v;
    }

    public static class TrainResult {
        private final boolean trained;
        private final int samples;
        private final double holdoutAccuracy;

        public TrainResult(boolean trained, int samples, double holdoutAccuracy) {
            this.trained = trained;
            this.samples = samples;
            this.holdoutAccuracy = holdoutAccuracy;
        }

        public boolean isTrained() {
            return trained;
        }

        public int getSamples() {
            return samples;
        }

        public double getHoldoutAccuracy() {
            return holdoutAccuracy;
        }
    }

    public static class Prediction {
        private final boolean intrusion;
        private final double probability;

        public Prediction(boolean intrusion, double probability) {
            this.intrusion = intrusion;
            this.probability = probability;
        }

        public boolean isIntrusion() {
            return intrusion;
        }

        public double getProbability() {
            return probability;
        }
    }

    public static class Status {
        private final boolean trained;
        private final int samples;
        private final String trainedAt;
        private final double lastHoldoutAccuracy;
        private final String modelType;

        public Status(boolean trained, int samples, String trainedAt, double lastHoldoutAccuracy, String modelType) {
            this.trained = trained;
            this.samples = samples;
            this.trainedAt = trainedAt;
            this.lastHoldoutAccuracy = lastHoldoutAccuracy;
            this.modelType = modelType;
        }

        public boolean isTrained() {
            return trained;
        }

        public int getSamples() {
            return samples;
        }

        public String getTrainedAt() {
            return trainedAt;
        }

        public double getLastHoldoutAccuracy() {
            return lastHoldoutAccuracy;
        }

        public String getModelType() {
            return modelType;
        }
    }

    public static class ShapContribution {
        public final String feature;
        public final double value;
        public final double contribution;

        public ShapContribution(String feature, double value, double contribution) {
            this.feature = feature;
            this.value = value;
            this.contribution = contribution;
        }
    }

    public static class Explanation {
        public final String modelType;
        public final double xgbProbability;
        public final Double wekaProbability;
        public final Double combinedProbability;
        public final double baseValue;
        public final List<ShapContribution> topContributions;

        public Explanation(String modelType, double xgbProbability, Double wekaProbability, Double combinedProbability, double baseValue, List<ShapContribution> topContributions) {
            this.modelType = modelType;
            this.xgbProbability = xgbProbability;
            this.wekaProbability = wekaProbability;
            this.combinedProbability = combinedProbability;
            this.baseValue = baseValue;
            this.topContributions = topContributions == null ? Collections.emptyList() : topContributions;
        }
    }
}
