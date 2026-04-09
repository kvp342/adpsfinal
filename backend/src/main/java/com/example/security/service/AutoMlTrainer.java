package com.example.security.service;

import com.example.security.model.SecurityLog;
import com.example.security.repository.SecurityLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class AutoMlTrainer {
    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");

    private final MlRandomForestService mlService;
    private final SecurityLogRepository logRepository;
    private final AtomicBoolean running = new AtomicBoolean(false);

    @Value("${apds.ml.autoTrain.enabled:true}")
    private boolean enabled;

    @Value("${apds.ml.autoTrain.modelType:RANDOM_FOREST}")
    private String modelType;

    @Value("${apds.ml.autoTrain.limit:2000}")
    private int limit;

    @Value("${apds.ml.autoTrain.minSamples:30}")
    private int minSamples;

    @Value("${apds.ml.autoTrain.retrainNewLogs:200}")
    private long retrainNewLogs;

    private volatile long lastTrainedTotal = 0;

    public AutoMlTrainer(MlRandomForestService mlService, SecurityLogRepository logRepository) {
        this.mlService = mlService;
        this.logRepository = logRepository;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onReady() {
        tick("startup");
    }

    @Scheduled(fixedDelayString = "${apds.ml.autoTrain.fixedDelayMs:30000}")
    public void scheduledTick() {
        tick("scheduled");
    }

    private void tick(String source) {
        if (!enabled) return;
        if (!running.compareAndSet(false, true)) return;
        try {
            long total = logRepository.count();
            MlRandomForestService.Status st = mlService.status();

            boolean needsInitialTrain = !st.isTrained() && total >= minSamples;
            boolean needsRetrain = st.isTrained()
                    && retrainNewLogs > 0
                    && total >= minSamples
                    && (total - lastTrainedTotal) >= retrainNewLogs;

            if (!needsInitialTrain && !needsRetrain) return;

            int safeLimit = Math.min(Math.max(limit, 50), 20000);
            List<SecurityLog> logs = logRepository.findAll(
                    PageRequest.of(0, safeLimit, Sort.by(Sort.Direction.DESC, "timestamp"))
            ).getContent();

            if (logs.size() < minSamples) return;

            try {
                MlRandomForestService.TrainResult res = mlService.train(logs, modelType);
                lastTrainedTotal = total;
                AUDIT.info("auto_ml_train source={} trained={} modelType={} samples={} holdoutAcc={}",
                        source,
                        res.isTrained(),
                        mlService.status().getModelType(),
                        res.getSamples(),
                        res.getHoldoutAccuracy());
            } catch (Exception e) {
                AUDIT.warn("auto_ml_train_failed source={} err={}", source, e.toString());
            }
        } finally {
            running.set(false);
        }
    }
}

