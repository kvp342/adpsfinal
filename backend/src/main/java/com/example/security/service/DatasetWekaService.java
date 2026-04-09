package com.example.security.service;

import com.example.security.model.ImportedDataset;
import com.example.security.repository.ImportedDatasetRepository;
import org.springframework.stereotype.Service;
import weka.classifiers.Classifier;
import weka.classifiers.Evaluation;
import weka.classifiers.bayes.NaiveBayes;
import weka.classifiers.functions.Logistic;
import weka.classifiers.meta.FilteredClassifier;
import weka.classifiers.trees.J48;
import weka.classifiers.trees.RandomForest;
import weka.classifiers.meta.Vote;
import weka.attributeSelection.InfoGainAttributeEval;
import weka.attributeSelection.Ranker;
import weka.core.Attribute;
import weka.core.DenseInstance;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.SelectedTag;
import weka.filters.Filter;
import weka.filters.supervised.attribute.AttributeSelection;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class DatasetWekaService {

    private final ImportedDatasetRepository importedDatasetRepository;

    private volatile Classifier classifier;
    private volatile Instances header;
    private volatile boolean trained;
    private volatile boolean training;
    private volatile int samples;
    private volatile double lastHoldoutAccuracy;
    private volatile String modelType;
    private volatile String datasetId;
    private volatile String datasetProfile;
    private volatile LocalDateTime trainedAt;
    private volatile String lastError;

    public DatasetWekaService(ImportedDatasetRepository importedDatasetRepository) {
        this.importedDatasetRepository = importedDatasetRepository;
    }

    public synchronized Status startTraining(String datasetId, String modelType, int maxRows) {
        if (datasetId == null || datasetId.isBlank()) throw new IllegalArgumentException("datasetId is required");
        ImportedDataset ds = importedDatasetRepository.findById(datasetId).orElseThrow(() -> new IllegalArgumentException("dataset not found"));
        DatasetProfile profile = DatasetProfile.valueOf(ds.getProfile());

        if (training) return status();

        this.training = true;
        this.trained = false;
        this.lastHoldoutAccuracy = 0.0;
        this.modelType = modelType;
        this.datasetId = ds.getId();
        this.datasetProfile = profile.name();
        this.trainedAt = LocalDateTime.now();
        this.lastError = null;
        this.classifier = null;
        this.header = null;

        int safeMax = Math.max(maxRows, 1);
        Thread t = new Thread(() -> {
            try {
                trainInternal(ds, profile, modelType, safeMax);
            } catch (Exception e) {
                synchronized (DatasetWekaService.this) {
                    lastError = e.getMessage() == null ? e.toString() : e.getMessage();
                    trained = false;
                    lastHoldoutAccuracy = 0.0;
                    classifier = null;
                    header = null;
                    trainedAt = LocalDateTime.now();
                }
            } finally {
                training = false;
            }
        }, "dataset-train");
        t.setDaemon(true);
        t.start();

        return status();
    }

    public Status status() {
        return new Status(trained, training, samples, trainedAt, lastHoldoutAccuracy, modelType, datasetId, datasetProfile, lastError);
    }

    public EvaluationResult evaluate(String datasetId, String modelType, int maxRows, int sampleCount, int folds) throws Exception {
        if (datasetId == null || datasetId.isBlank()) throw new IllegalArgumentException("datasetId is required");
        ImportedDataset ds = importedDatasetRepository.findById(datasetId).orElseThrow(() -> new IllegalArgumentException("dataset not found"));
        DatasetProfile profile = DatasetProfile.valueOf(ds.getProfile());

        int safeMax = Math.max(maxRows, 1);
        int safeSamples = Math.min(Math.max(sampleCount, 0), 50);
        int safeFolds = Math.min(Math.max(folds, 2), 10);

        Instances data = loadDataset(Path.of(ds.getStoredPath()), profile, safeMax);
        if (data.numInstances() <= 0) {
            return new EvaluationResult(false, modelType, ds.getId(), profile.name(), 0, safeFolds, 0.0, 0.0, 0, 0, 0, 0, Collections.emptyList(), "Dataset has no rows");
        }

        Instances randomized = new Instances(data);
        randomized.randomize(new Random(42));

        Classifier cls = buildClassifier(modelType);
        cls.buildClassifier(randomized);

        Evaluation evalTrain = new Evaluation(randomized);
        evalTrain.evaluateModel(cls, randomized);
        double trainAcc = evalTrain.pctCorrect() / 100.0;

        int effectiveFolds = Math.min(safeFolds, Math.max(randomized.numInstances(), 2));
        Evaluation evalCv = new Evaluation(randomized);
        Classifier cvCls = buildClassifier(modelType);
        evalCv.crossValidateModel(cvCls, randomized, effectiveFolds, new Random(42));
        double cvAcc = evalCv.pctCorrect() / 100.0;

        double[][] cmCv = evalCv.confusionMatrix();
        long tn = cmCv.length > 0 && cmCv[0].length > 0 ? Math.round(cmCv[0][0]) : 0;
        long fp = cmCv.length > 0 && cmCv[0].length > 1 ? Math.round(cmCv[0][1]) : 0;
        long fn = cmCv.length > 1 && cmCv[1].length > 0 ? Math.round(cmCv[1][0]) : 0;
        long tp = cmCv.length > 1 && cmCv[1].length > 1 ? Math.round(cmCv[1][1]) : 0;

        List<SamplePrediction> samplesOut = safeSamples == 0 ? Collections.emptyList() : samplePredictions(cls, randomized, safeSamples);

        return new EvaluationResult(true, modelType, ds.getId(), profile.name(), randomized.numInstances(), effectiveFolds, trainAcc, cvAcc, tn, fp, fn, tp, samplesOut, null);
    }

    private synchronized void trainInternal(ImportedDataset ds, DatasetProfile profile, String modelType, int maxRows) throws Exception {
        Instances data = loadDataset(Path.of(ds.getStoredPath()), profile, maxRows);
        this.samples = data.numInstances();
        if (data.numInstances() < 30) {
            this.classifier = null;
            this.header = null;
            this.trained = false;
            this.lastHoldoutAccuracy = 0.0;
            this.modelType = modelType;
            this.datasetId = ds.getId();
            this.datasetProfile = profile.name();
            this.trainedAt = LocalDateTime.now();
            this.lastError = "Not enough rows to train (need >= 30)";
            return;
        }

        Instances randomized = new Instances(data);
        randomized.randomize(new Random(42));
        int trainSize = (int) Math.round(randomized.numInstances() * 0.8);
        int testSize = randomized.numInstances() - trainSize;
        Instances train = new Instances(randomized, 0, trainSize);
        Instances test = new Instances(randomized, trainSize, testSize);

        Classifier cls = buildClassifier(modelType);
        cls.buildClassifier(train);

        Evaluation eval = new Evaluation(train);
        eval.evaluateModel(cls, test);

        this.classifier = cls;
        this.header = new Instances(data, 0);
        this.trained = true;
        this.lastHoldoutAccuracy = eval.pctCorrect() / 100.0;
        this.modelType = modelType;
        this.datasetId = ds.getId();
        this.datasetProfile = profile.name();
        this.trainedAt = LocalDateTime.now();
        this.lastError = null;
    }

    private Classifier buildClassifier(String model) throws Exception {
        AttributeSelection attrSel = new AttributeSelection();
        InfoGainAttributeEval eval = new InfoGainAttributeEval();
        Ranker ranker = new Ranker();
        ranker.setNumToSelect(40);
        attrSel.setEvaluator(eval);
        attrSel.setSearch(ranker);

        if (model != null && model.equalsIgnoreCase("ENSEMBLE")) {
            Vote vote = new Vote();
            vote.setCombinationRule(new SelectedTag(Vote.AVERAGE_RULE, Vote.TAGS_RULES));

            RandomForest rf = new RandomForest();
            rf.setNumIterations(80);
            rf.setSeed(42);

            J48 j48 = new J48();
            NaiveBayes nb = new NaiveBayes();
            Logistic log = new Logistic();

            vote.setClassifiers(new Classifier[]{
                    wrapWithFilter(rf, attrSel),
                    wrapWithFilter(j48, attrSel),
                    wrapWithFilter(nb, attrSel),
                    wrapWithFilter(log, attrSel)
            });
            return vote;
        }

        RandomForest rf = new RandomForest();
        rf.setNumIterations(120);
        rf.setSeed(42);
        return wrapWithFilter(rf, attrSel);
    }

    private Classifier wrapWithFilter(Classifier base, Filter filter) {
        FilteredClassifier fc = new FilteredClassifier();
        try {
            fc.setFilter(Filter.makeCopy(filter));
        } catch (Exception e) {
            fc.setFilter(filter);
        }
        fc.setClassifier(base);
        return fc;
    }

    private List<SamplePrediction> samplePredictions(Classifier cls, Instances data, int sampleCount) throws Exception {
        List<Integer> benign = new ArrayList<>();
        List<Integer> attack = new ArrayList<>();
        for (int i = 0; i < data.numInstances(); i++) {
            Instance inst = data.instance(i);
            int actual = (int) inst.classValue();
            if (actual == 1) attack.add(i);
            else benign.add(i);
        }

        Collections.shuffle(benign, new Random(7));
        Collections.shuffle(attack, new Random(7));

        int attackTake = Math.min(sampleCount / 2, attack.size());
        int benignTake = Math.min(sampleCount - attackTake, benign.size());

        List<Integer> chosen = new ArrayList<>();
        chosen.addAll(attack.subList(0, attackTake));
        chosen.addAll(benign.subList(0, benignTake));
        Collections.shuffle(chosen, new Random(7));

        List<SamplePrediction> out = new ArrayList<>();
        for (Integer idx : chosen) {
            Instance inst = data.instance(idx);
            double[] dist = cls.distributionForInstance(inst);
            int pred = 0;
            double best = -1.0;
            for (int i = 0; i < dist.length; i++) {
                if (dist[i] > best) {
                    best = dist[i];
                    pred = i;
                }
            }
            int actual = (int) inst.classValue();
            double prob = dist.length > 1 ? dist[1] : 0.0;
            out.add(new SamplePrediction(idx, actual, pred, prob));
        }
        return out;
    }

    private Instances loadDataset(Path path, DatasetProfile profile, int maxRows) throws Exception {
        if (profile == DatasetProfile.CICIDS2017) {
            return loadCicidsCsv(path, maxRows);
        }
        if (profile == DatasetProfile.NSL_KDD) {
            return loadNslKddCsv(path, maxRows, true);
        }
        return loadNslKddCsv(path, maxRows, false);
    }

    private Instances loadCicidsCsv(Path path, int maxRows) throws Exception {
        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String headerLine = br.readLine();
            if (headerLine == null) return emptyBinaryDataset("cicids");

            List<String> header = CsvUtils.parseLine(headerLine);
            int labelIdx = findLabelIndex(header);
            if (labelIdx < 0) labelIdx = header.size() - 1;

            List<Integer> featureIdxs = new ArrayList<>();
            List<Attribute> attrs = new ArrayList<>();
            Set<String> usedAttrNames = new HashSet<>();
            for (int i = 0; i < header.size(); i++) {
                if (i == labelIdx) continue;
                String name = sanitizeAttrName(header.get(i));
                if (shouldIgnoreCicidsColumn(name)) continue;
                name = uniqueAttrName(name, usedAttrNames);
                featureIdxs.add(i);
                attrs.add(new Attribute(name));
            }
            ArrayList<String> classVals = new ArrayList<>();
            classVals.add("0");
            classVals.add("1");
            attrs.add(new Attribute("intrusion", classVals));

            Instances data = new Instances("cicids2017", new ArrayList<>(attrs), Math.min(maxRows, 1000));
            data.setClassIndex(data.numAttributes() - 1);

            String line;
            int rows = 0;
            while ((line = br.readLine()) != null && rows < maxRows) {
                List<String> cols = CsvUtils.parseLine(line);
                if (cols.size() <= labelIdx) continue;
                DenseInstance inst = new DenseInstance(data.numAttributes());
                inst.setDataset(data);

                for (int j = 0; j < featureIdxs.size(); j++) {
                    int idx = featureIdxs.get(j);
                    double v = parseDoubleSafe(idx < cols.size() ? cols.get(idx) : null);
                    inst.setValue(j, v);
                }

                String lbl = cols.get(labelIdx);
                boolean attack = lbl != null && !lbl.trim().equalsIgnoreCase("BENIGN");
                inst.setValue(data.classIndex(), attack ? "1" : "0");
                data.add(inst);
                rows++;
            }
            return data;
        }
    }

    private Instances loadNslKddCsv(Path path, int maxRows, boolean hasDifficultyColumn) throws Exception {
        int protoIdx = 1;
        int serviceIdx = 2;
        int flagIdx = 3;

        Set<String> protos = new LinkedHashSet<>();
        Set<String> services = new LinkedHashSet<>();
        Set<String> flags = new LinkedHashSet<>();

        List<List<String>> cached = new ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null && cached.size() < maxRows) {
                if (line.isBlank()) continue;
                List<String> cols = CsvUtils.parseLine(line);
                if (cols.size() < 10) continue;
                cached.add(cols);
                if (cols.size() > protoIdx) protos.add(cols.get(protoIdx));
                if (cols.size() > serviceIdx) services.add(cols.get(serviceIdx));
                if (cols.size() > flagIdx) flags.add(cols.get(flagIdx));
            }
        }

        List<Attribute> attrs = new ArrayList<>();
        List<Integer> numericIdxs = new ArrayList<>();

        int labelIdx = -1;
        for (List<String> cols : cached) {
            if (cols.size() >= 43) {
                labelIdx = cols.size() - 2;
                hasDifficultyColumn = true;
                break;
            }
            if (cols.size() == 42) {
                labelIdx = cols.size() - 1;
                break;
            }
        }
        if (labelIdx < 0) return emptyBinaryDataset("kdd");

        int lastFeatureIdx = hasDifficultyColumn ? labelIdx - 1 : labelIdx - 1;
        for (int i = 0; i <= lastFeatureIdx; i++) {
            if (i == protoIdx || i == serviceIdx || i == flagIdx) continue;
            numericIdxs.add(i);
            attrs.add(new Attribute("f" + i));
        }

        for (String p : protos) attrs.add(new Attribute("protocol_" + sanitizeAttrName(p)));
        for (String s : services) attrs.add(new Attribute("service_" + sanitizeAttrName(s)));
        for (String f : flags) attrs.add(new Attribute("flag_" + sanitizeAttrName(f)));

        ArrayList<String> classVals = new ArrayList<>();
        classVals.add("0");
        classVals.add("1");
        attrs.add(new Attribute("intrusion", classVals));

        Instances data = new Instances(hasDifficultyColumn ? "nsl_kdd" : "kdd99", new ArrayList<>(attrs), Math.min(maxRows, 1000));
        data.setClassIndex(data.numAttributes() - 1);

        List<String> protoList = new ArrayList<>(protos);
        List<String> serviceList = new ArrayList<>(services);
        List<String> flagList = new ArrayList<>(flags);

        for (List<String> cols : cached) {
            if (cols.size() <= labelIdx) continue;
            DenseInstance inst = new DenseInstance(data.numAttributes());
            inst.setDataset(data);

            int pos = 0;
            for (Integer nIdx : numericIdxs) {
                double v = parseDoubleSafe(nIdx < cols.size() ? cols.get(nIdx) : null);
                inst.setValue(pos, v);
                pos++;
            }

            String proto = cols.size() > protoIdx ? cols.get(protoIdx) : "";
            for (String p : protoList) {
                inst.setValue(pos, p.equals(proto) ? 1.0 : 0.0);
                pos++;
            }

            String service = cols.size() > serviceIdx ? cols.get(serviceIdx) : "";
            for (String s : serviceList) {
                inst.setValue(pos, s.equals(service) ? 1.0 : 0.0);
                pos++;
            }

            String flag = cols.size() > flagIdx ? cols.get(flagIdx) : "";
            for (String f : flagList) {
                inst.setValue(pos, f.equals(flag) ? 1.0 : 0.0);
                pos++;
            }

            String rawLabel = cols.get(labelIdx);
            String clean = rawLabel == null ? "" : rawLabel.trim();
            if (clean.endsWith(".")) clean = clean.substring(0, clean.length() - 1);
            boolean attack = !clean.equalsIgnoreCase("normal");
            inst.setValue(data.classIndex(), attack ? "1" : "0");

            data.add(inst);
        }
        return data;
    }

    private boolean shouldIgnoreCicidsColumn(String headerName) {
        String k = headerName == null ? "" : headerName.toLowerCase(Locale.ROOT);
        if (k.equals("flow_id") || k.equals("flowid")) return true;
        if (k.contains("source_ip") || k.contains("destination_ip")) return true;
        if (k.contains("src_ip") || k.contains("dst_ip")) return true;
        if (k.equals("timestamp")) return true;
        return false;
    }

    private int findLabelIndex(List<String> header) {
        if (header == null) return -1;
        for (int i = 0; i < header.size(); i++) {
            String h = header.get(i);
            if (h == null) continue;
            String k = h.trim().toLowerCase(Locale.ROOT);
            if (k.equals("label") || k.equals("class") || k.equals("attack") || k.equals("target")) return i;
        }
        return -1;
    }

    private double parseDoubleSafe(String s) {
        if (s == null) return 0.0;
        String t = s.trim();
        if (t.isEmpty()) return 0.0;
        if (t.equalsIgnoreCase("nan")) return 0.0;
        if (t.equalsIgnoreCase("infinity") || t.equalsIgnoreCase("inf")) return 0.0;
        if (t.equalsIgnoreCase("infinite")) return 0.0;
        try {
            return Double.parseDouble(t);
        } catch (Exception e) {
            return 0.0;
        }
    }

    private String sanitizeAttrName(String s) {
        if (s == null || s.isBlank()) return "x";
        return s.trim().replaceAll("[^a-zA-Z0-9_]+", "_");
    }

    private String uniqueAttrName(String base, Set<String> used) {
        String b = base == null || base.isBlank() ? "x" : base;
        if (used.add(b)) return b;
        int i = 2;
        while (true) {
            String candidate = b + "_" + i;
            if (used.add(candidate)) return candidate;
            i++;
        }
    }

    private Instances emptyBinaryDataset(String name) {
        ArrayList<Attribute> attrs = new ArrayList<>();
        attrs.add(new Attribute("f0"));
        ArrayList<String> classVals = new ArrayList<>();
        classVals.add("0");
        classVals.add("1");
        attrs.add(new Attribute("intrusion", classVals));
        Instances data = new Instances(name, attrs, 0);
        data.setClassIndex(data.numAttributes() - 1);
        return data;
    }

    public static final class Status {
        public final boolean trained;
        public final boolean training;
        public final int samples;
        public final LocalDateTime trainedAt;
        public final double lastHoldoutAccuracy;
        public final String modelType;
        public final String datasetId;
        public final String datasetProfile;
        public final String lastError;

        public Status(boolean trained, boolean training, int samples, LocalDateTime trainedAt, double lastHoldoutAccuracy, String modelType, String datasetId, String datasetProfile, String lastError) {
            this.trained = trained;
            this.training = training;
            this.samples = samples;
            this.trainedAt = trainedAt;
            this.lastHoldoutAccuracy = lastHoldoutAccuracy;
            this.modelType = modelType;
            this.datasetId = datasetId;
            this.datasetProfile = datasetProfile;
            this.lastError = lastError;
        }
    }

    public static final class SamplePrediction {
        public final int rowIndex;
        public final int actual;
        public final int predicted;
        public final double intrusionProbability;

        public SamplePrediction(int rowIndex, int actual, int predicted, double intrusionProbability) {
            this.rowIndex = rowIndex;
            this.actual = actual;
            this.predicted = predicted;
            this.intrusionProbability = intrusionProbability;
        }
    }

    public static final class EvaluationResult {
        public final boolean ok;
        public final String modelType;
        public final String datasetId;
        public final String datasetProfile;
        public final int rows;
        public final int folds;
        public final double trainAccuracy;
        public final double crossValAccuracy;
        public final long tn;
        public final long fp;
        public final long fn;
        public final long tp;
        public final List<SamplePrediction> samples;
        public final String error;

        public EvaluationResult(boolean ok, String modelType, String datasetId, String datasetProfile, int rows, int folds, double trainAccuracy, double crossValAccuracy, long tn, long fp, long fn, long tp, List<SamplePrediction> samples, String error) {
            this.ok = ok;
            this.modelType = modelType;
            this.datasetId = datasetId;
            this.datasetProfile = datasetProfile;
            this.rows = rows;
            this.folds = folds;
            this.trainAccuracy = trainAccuracy;
            this.crossValAccuracy = crossValAccuracy;
            this.tn = tn;
            this.fp = fp;
            this.fn = fn;
            this.tp = tp;
            this.samples = samples == null ? Collections.emptyList() : samples;
            this.error = error;
        }
    }
}
