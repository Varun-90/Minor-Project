/**
 * NetShield AI Machine Learning Pipeline Service
 * Trains, evaluates (zero data leakage), serializes, and serves the versioned
 * Random Forest intrusion detection model (Binary + Multiclass).
 */

import fs from 'fs';
import path from 'path';
import {
  BinaryLabel,
  CleaningReport,
  FEATURE_LABELS,
  FEATURE_NAMES,
  FeatureName,
  PreprocessorStats,
  ProtocolName,
  RawFlowRecord,
  SeverityLevel,
  deduplicateRawFlows,
  extractRawVector,
  fitPreprocessor,
  mapCsvRowToRawFlow,
  normalizeProtocol,
  parseCsvText,
  parseNumeric,
  transformVector,
} from './schema.ts';
import { buildCicIds2017BenchmarkDataset } from './cicIdsDataset.ts';
import {
  RandomForestClassifier,
  RandomForestModelData,
  stratifiedTrainTestSplit,
} from './randomForest.ts';

export interface ConfusionMatrix {
  tn: number;
  fp: number;
  fn: number;
  tp: number;
}

export interface ClassMetric {
  label: string;
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface ModelEvaluationMetrics {
  version: string;
  algorithm: string;
  dataset: string;
  trainedAt: string;
  artifactPath: string;
  isActive: boolean;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  confusionMatrix: ConfusionMatrix;
  trainSamples: number;
  testSamples: number;
  nEstimators: number;
  maxDepth: number;
  cleaningReport: CleaningReport;
  featureImportances: { feature: FeatureName; label: string; importance: number }[];
  multiclassMetrics: ClassMetric[];
}

export interface ModelArtifact {
  version: string;
  trainedAt: string;
  preprocessor: PreprocessorStats;
  binaryModel: RandomForestModelData;
  multiclassModel: RandomForestModelData;
  metrics: ModelEvaluationMetrics;
}

export interface AlertPolicy {
  criticalThreshold: number;
  highThreshold: number;
  mediumThreshold: number;
  lowThreshold: number;
}

export const DEFAULT_ALERT_POLICY: AlertPolicy = {
  criticalThreshold: 0.9,
  highThreshold: 0.75,
  mediumThreshold: 0.6,
  lowThreshold: 0.5,
};

export interface PredictionResult {
  eventTime: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: ProtocolName;
  prediction: BinaryLabel;
  attackType: string;
  score: number;
  severity: SeverityLevel;
  modelVersion: string;
  flowDuration: number;
  totalFwdPackets: number;
  totalBwdPackets: number;
  totalBytes: number;
  flowBytesPerSec: number;
  flowPacketsPerSec: number;
  synFlagCount: number;
  ackFlagCount: number;
  featureMap: Record<FeatureName, number>;
  treeVotes: Record<string, number>;
  topContributors: { feature: FeatureName; label: string; value: number; importance: number }[];
}

const ARTIFACT_DIR = path.resolve(process.cwd(), 'ml', 'artifacts');

export class ThreatDetectionPipeline {
  private binaryRf: RandomForestClassifier;
  private multiclassRf: RandomForestClassifier;
  private preprocessor: PreprocessorStats;
  public activeMetrics: ModelEvaluationMetrics;
  public evaluationHistory: ModelEvaluationMetrics[] = [];
  private versionCounter = 1;

  constructor() {
    const initial = this.loadOrTrainInitial();
    this.preprocessor = initial.preprocessor;
    this.binaryRf = new RandomForestClassifier(initial.binaryModel);
    this.multiclassRf = new RandomForestClassifier(initial.multiclassModel);
    this.activeMetrics = initial.metrics;
    this.evaluationHistory = [initial.metrics];
  }

  private loadOrTrainInitial(): ModelArtifact {
    const defaultPath = path.join(ARTIFACT_DIR, 'netshield_rf_v1.0.0.json');
    if (fs.existsSync(defaultPath)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(defaultPath, 'utf-8')) as ModelArtifact;
        if (parsed?.binaryModel?.trees?.length > 0 && parsed?.metrics?.confusionMatrix) {
          return parsed;
        }
      } catch {
        // Retrain cleanly if artifact is unreadable
      }
    }
    return this.runTrainingPipeline({ version: 'v1.0.0', nEstimators: 25, maxDepth: 8, seed: 2017 });
  }

  public trainNewVersion(options: { nEstimators?: number; maxDepth?: number } = {}): ModelEvaluationMetrics {
    this.versionCounter++;
    const version = `v1.${this.versionCounter - 1}.0`;
    const nEstimators = Math.min(Math.max(Math.round(options.nEstimators ?? 30), 5), 100);
    const maxDepth = Math.min(Math.max(Math.round(options.maxDepth ?? 9), 3), 20);
    const seed = 2017 + this.versionCounter * 97;

    const artifact = this.runTrainingPipeline({ version, nEstimators, maxDepth, seed });
    this.preprocessor = artifact.preprocessor;
    this.binaryRf = new RandomForestClassifier(artifact.binaryModel);
    this.multiclassRf = new RandomForestClassifier(artifact.multiclassModel);

    this.evaluationHistory = this.evaluationHistory.map((m) => ({ ...m, isActive: false }));
    this.activeMetrics = artifact.metrics;
    this.evaluationHistory.unshift(artifact.metrics);
    return artifact.metrics;
  }

  private runTrainingPipeline(params: {
    version: string;
    nEstimators: number;
    maxDepth: number;
    seed: number;
  }): ModelArtifact {
    // Step 1: Load CIC-IDS2017 network-flow records
    const rawDataset = buildCicIds2017BenchmarkDataset(params.seed);

    // Step 2: Clean duplicates
    const { unique, duplicatesRemoved } = deduplicateRawFlows(rawDataset);

    // Step 3: Extract raw numeric vectors & labels
    const rawVectors = unique.map(extractRawVector);
    const multiLabels = unique.map((r) => (r.label && r.label.trim() ? r.label.trim() : 'BENIGN'));
    const binaryLabels: BinaryLabel[] = multiLabels.map((l) =>
      l.toUpperCase() === 'BENIGN' ? 'Normal' : 'Attack'
    );

    // Step 4: Stratified 80/20 Train/Test Split BEFORE fitting preprocessor (zero leakage)
    const { trainIndices, testIndices } = stratifiedTrainTestSplit(unique, multiLabels, 0.2, params.seed);

    const trainRawX = trainIndices.map((i) => rawVectors[i]);
    const testRawX = testIndices.map((i) => rawVectors[i]);

    // Step 5: Fit median imputer & infinity cap strictly on training set
    const preprocessor = fitPreprocessor(trainRawX);

    let missingValuesImputed = 0;
    let infiniteValuesReplaced = 0;

    const trainX = trainRawX.map((vec) => {
      const res = transformVector(vec, preprocessor);
      missingValuesImputed += res.missingCount;
      infiniteValuesReplaced += res.infiniteCount;
      return res.vector;
    });
    const testX = testRawX.map((vec) => {
      const res = transformVector(vec, preprocessor);
      missingValuesImputed += res.missingCount;
      infiniteValuesReplaced += res.infiniteCount;
      return res.vector;
    });

    const trainBinaryY = trainIndices.map((i) => binaryLabels[i]);
    const testBinaryY = testIndices.map((i) => binaryLabels[i]);
    const trainMultiY = trainIndices.map((i) => multiLabels[i]);
    const testMultiY = testIndices.map((i) => multiLabels[i]);

    // Step 6: Train Binary and Multiclass Random Forest Classifiers
    const binaryRf = new RandomForestClassifier().fit(trainX, trainBinaryY, {
      nEstimators: params.nEstimators,
      maxDepth: params.maxDepth,
      minSamplesSplit: 4,
      seed: params.seed + 11,
    });

    const multiclassRf = new RandomForestClassifier().fit(trainX, trainMultiY, {
      nEstimators: params.nEstimators,
      maxDepth: params.maxDepth,
      minSamplesSplit: 4,
      seed: params.seed + 29,
    });

    // Step 7: Evaluate strictly on unseen test split
    let tn = 0;
    let fp = 0;
    let fn = 0;
    let tp = 0;

    for (let i = 0; i < testX.length; i++) {
      const pred = binaryRf.predict(testX[i]).label as BinaryLabel;
      const actual = testBinaryY[i];
      if (actual === 'Attack' && pred === 'Attack') tp++;
      else if (actual === 'Normal' && pred === 'Normal') tn++;
      else if (actual === 'Normal' && pred === 'Attack') fp++;
      else if (actual === 'Attack' && pred === 'Normal') fn++;
    }

    const total = Math.max(tp + tn + fp + fn, 1);
    const accuracy = Number(((tp + tn) / total).toFixed(4));
    const precision = tp + fp > 0 ? Number((tp / (tp + fp)).toFixed(4)) : 0;
    const recall = tp + fn > 0 ? Number((tp / (tp + fn)).toFixed(4)) : 0;
    const f1Score =
      precision + recall > 0 ? Number(((2 * precision * recall) / (precision + recall)).toFixed(4)) : 0;
    const falsePositiveRate = fp + tn > 0 ? Number((fp / (fp + tn)).toFixed(4)) : 0;

    // Multiclass evaluation on test split
    const uniqueClasses = Array.from(new Set(testMultiY)).sort();
    const multiPreds = testX.map((x) => multiclassRf.predict(x).label);
    const multiclassMetrics: ClassMetric[] = uniqueClasses.map((cls) => {
      let cTp = 0;
      let cFp = 0;
      let cFn = 0;
      let support = 0;
      for (let i = 0; i < testMultiY.length; i++) {
        if (testMultiY[i] === cls) support++;
        if (testMultiY[i] === cls && multiPreds[i] === cls) cTp++;
        else if (testMultiY[i] !== cls && multiPreds[i] === cls) cFp++;
        else if (testMultiY[i] === cls && multiPreds[i] !== cls) cFn++;
      }
      const p = cTp + cFp > 0 ? Number((cTp / (cTp + cFp)).toFixed(4)) : 0;
      const r = cTp + cFn > 0 ? Number((cTp / (cTp + cFn)).toFixed(4)) : 0;
      const f = p + r > 0 ? Number(((2 * p * r) / (p + r)).toFixed(4)) : 0;
      return { label: cls, precision: p, recall: r, f1: f, support };
    });

    const featureImportances = FEATURE_NAMES.map((feature, idx) => ({
      feature,
      label: FEATURE_LABELS[feature],
      importance: binaryRf.data.featureImportances[idx] ?? 0,
    })).sort((a, b) => b.importance - a.importance);

    const artifactRelPath = `ml/artifacts/netshield_rf_${params.version}.json`;
    const trainedAt = new Date().toISOString();

    const metrics: ModelEvaluationMetrics = {
      version: params.version,
      algorithm: 'RandomForestClassifier',
      dataset: 'CIC-IDS2017',
      trainedAt,
      artifactPath: artifactRelPath,
      isActive: true,
      accuracy,
      precision,
      recall,
      f1Score,
      falsePositiveRate,
      confusionMatrix: { tn, fp, fn, tp },
      trainSamples: trainX.length,
      testSamples: testX.length,
      nEstimators: params.nEstimators,
      maxDepth: params.maxDepth,
      cleaningReport: {
        totalRawRows: rawDataset.length,
        duplicatesRemoved,
        missingValuesImputed,
        infiniteValuesReplaced,
        validRowsRetained: unique.length,
      },
      featureImportances,
      multiclassMetrics,
    };

    const artifact: ModelArtifact = {
      version: params.version,
      trainedAt,
      preprocessor,
      binaryModel: binaryRf.data,
      multiclassModel: multiclassRf.data,
      metrics,
    };

    // Step 8: Persist versioned artifact
    try {
      fs.mkdirSync(ARTIFACT_DIR, { recursive: true });
      fs.writeFileSync(
        path.join(ARTIFACT_DIR, `netshield_rf_${params.version}.json`),
        JSON.stringify(artifact)
      );
    } catch (err) {
      console.error('Failed to persist model artifact:', err);
    }

    return artifact;
  }

  public computeSeverity(prediction: BinaryLabel, score: number, policy: AlertPolicy = DEFAULT_ALERT_POLICY): SeverityLevel {
    if (prediction === 'Normal' && score < policy.lowThreshold) return 'None';
    if (score >= policy.criticalThreshold) return 'Critical';
    if (score >= policy.highThreshold) return 'High';
    if (score >= policy.mediumThreshold) return 'Medium';
    if (score >= policy.lowThreshold) return 'Low';
    return 'None';
  }

  public predictFlow(raw: RawFlowRecord, policy: AlertPolicy = DEFAULT_ALERT_POLICY): PredictionResult {
    const proto = normalizeProtocol(raw.protocol);
    const rawVec = extractRawVector(raw);
    const { vector } = transformVector(rawVec, this.preprocessor);

    const binaryOut = this.binaryRf.predict(vector);
    const attackProb = binaryOut.probabilities['Attack'] ?? 0;
    const prediction: BinaryLabel = attackProb >= policy.lowThreshold ? 'Attack' : 'Normal';

    let attackType = 'BENIGN';
    if (prediction === 'Attack') {
      const multiOut = this.multiclassRf.predict(vector);
      if (multiOut.label !== 'BENIGN') {
        attackType = multiOut.label;
      } else {
        // Select highest non-BENIGN class probability
        let bestAtk = 'Suspicious Flow';
        let bestProb = -1;
        for (const [cls, p] of Object.entries(multiOut.probabilities)) {
          if (cls !== 'BENIGN' && p > bestProb) {
            bestProb = p;
            bestAtk = cls;
          }
        }
        attackType = bestAtk;
      }
    }

    const severity = this.computeSeverity(prediction, attackProb, policy);

    const featureMap = {} as Record<FeatureName, number>;
    FEATURE_NAMES.forEach((name, idx) => {
      featureMap[name] = Number(vector[idx].toFixed(2));
    });

    const topContributors = this.activeMetrics.featureImportances.slice(0, 6).map((fi) => ({
      feature: fi.feature,
      label: fi.label,
      value: featureMap[fi.feature],
      importance: fi.importance,
    }));

    const srcPort = Math.min(Math.max(Math.round(parseNumeric(raw.srcPort) || 51420), 0), 65535);
    const dstPort = Math.min(Math.max(Math.round(vector[0]), 0), 65535);

    return {
      eventTime: raw.eventTime && raw.eventTime.trim() ? raw.eventTime.trim() : new Date().toISOString(),
      srcIp: (raw.srcIp && raw.srcIp.trim()) || '192.168.10.15',
      dstIp: (raw.dstIp && raw.dstIp.trim()) || '192.168.10.50',
      srcPort,
      dstPort,
      protocol: proto.name,
      prediction,
      attackType,
      score: Number(attackProb.toFixed(4)),
      severity,
      modelVersion: this.activeMetrics.version,
      flowDuration: featureMap.flowDuration,
      totalFwdPackets: Math.round(featureMap.totalFwdPackets),
      totalBwdPackets: Math.round(featureMap.totalBwdPackets),
      totalBytes: Math.round(featureMap.totalLenFwdPackets + featureMap.totalLenBwdPackets),
      flowBytesPerSec: featureMap.flowBytesPerSec,
      flowPacketsPerSec: featureMap.flowPacketsPerSec,
      synFlagCount: Math.round(featureMap.synFlagCount),
      ackFlagCount: Math.round(featureMap.ackFlagCount),
      featureMap,
      treeVotes: binaryOut.treeVotes,
      topContributors,
    };
  }

  public analyzeCsv(csvText: string, policy: AlertPolicy = DEFAULT_ALERT_POLICY): {
    predictions: PredictionResult[];
    cleaningReport: CleaningReport;
  } {
    const parsedRows = parseCsvText(csvText);
    if (parsedRows.length === 0) {
      throw new Error('CSV file contains no valid data rows. Ensure header and at least one flow record exist.');
    }

    const rawFlows = parsedRows.map(mapCsvRowToRawFlow);
    const { unique, duplicatesRemoved } = deduplicateRawFlows(rawFlows);

    let missingValuesImputed = 0;
    let infiniteValuesReplaced = 0;
    const predictions: PredictionResult[] = [];

    for (const raw of unique) {
      const vec = extractRawVector(raw);
      const { missingCount, infiniteCount } = transformVector(vec, this.preprocessor);
      missingValuesImputed += missingCount;
      infiniteValuesReplaced += infiniteCount;
      predictions.push(this.predictFlow(raw, policy));
    }

    return {
      predictions,
      cleaningReport: {
        totalRawRows: parsedRows.length,
        duplicatesRemoved,
        missingValuesImputed,
        infiniteValuesReplaced,
        validRowsRetained: unique.length,
      },
    };
  }

  public generateSampleCsv(): string {
    const headers = [
      'Timestamp',
      'Source IP',
      'Destination IP',
      'Source Port',
      'Destination Port',
      'Protocol',
      'Flow Duration',
      'Total Fwd Packets',
      'Total Backward Packets',
      'Total Length of Fwd Packets',
      'Total Length of Bwd Packets',
      'Fwd Packet Length Mean',
      'Bwd Packet Length Mean',
      'Flow Bytes/s',
      'Flow Packets/s',
      'Flow IAT Mean',
      'SYN Flag Count',
      'ACK Flag Count',
      'FIN Flag Count',
      'RST Flag Count',
      'PSH Flag Count',
    ];
    const now = Date.now();
    const ts = (offsetMin: number) => new Date(now - offsetMin * 60000).toISOString();
    const sampleRows = [
      [ts(45), '192.168.10.12', '104.16.132.229', 52410, 443, 'TCP', 420000, 14, 18, 2240, 14800, 160, 822.2, 40571.4, 76.2, 13548.4, 1, 24, 1, 0, 8],
      [ts(42), '172.16.0.1', '192.168.10.50', 48122, 80, 'TCP', 180000, 195, 2, 3120, 64, 16, 32, 17688.9, 1094.4, 918.4, 18, 3, 0, 2, 0],
      [ts(39), '192.168.10.8', '8.8.8.8', 61004, 53, 'UDP', 2400, 2, 2, 118, 280, 59, 140, 165833.3, 1666.7, 800, 0, 0, 0, 0, 0],
      [ts(36), '185.220.101.42', '192.168.10.19', 55910, 22, 'TCP', 420, 2, 1, 12, 0, 6, 0, 28571.4, 7142.8, 210, 1, 1, 0, 2, 0],
      [ts(33), '45.155.205.91', '192.168.10.50', 44120, 80, 'TCP', 28500000, 14, 11, 4480, 26400, 320, 2400, 1083.5, 0.88, 1187500, 1, 9, 1, 0, 2],
      [ts(30), '192.168.10.14', '172.217.10.46', 49811, 443, 'TCP', 980000, 22, 31, 4180, 31200, 190, 1006.5, 36102.0, 54.1, 18846.2, 1, 38, 1, 0, 10],
      [ts(27), '172.16.0.1', '192.168.10.50', 51200, 22, 'TCP', 6400000, 32, 28, 4160, 4480, 130, 160, 1350.0, 9.38, 108474.6, 1, 46, 1, 2, 24],
      [ts(24), '192.168.10.25', '205.174.165.73', 59122, 8080, 'TCP', 210000, 7, 6, 448, 360, 64, 60, 3847.6, 61.9, 17500, 1, 9, 1, 0, 5],
      [ts(21), '198.51.100.24', '192.168.10.50', 50118, 443, 'TCP', 11200000, 36, 26, 26640, 9880, 740, 380, 3260.7, 5.54, 183606.6, 1, 34, 1, 0, 22],
      [ts(18), '192.168.10.9', '151.101.1.69', 53402, 443, 'TCP', 610000, 11, 15, 1980, 11400, 180, 760, 21934.4, 42.6, 24400, 1, 18, 1, 0, 6],
      [ts(15), '172.16.0.1', '192.168.10.50', 60211, 80, 'TCP', 95000, 240, 1, 4800, 24, 20, 24, 'Infinity', 2536.8, 395.8, 22, 1, 0, 1, 0],
      [ts(12), '185.220.101.42', '192.168.10.8', 41890, 3306, 'TCP', 310, 1, 1, 0, 0, 0, 0, 0, 6451.6, 310, 1, 1, 0, 1, 0],
    ];
    return [headers.join(','), ...sampleRows.map((r) => r.join(','))].join('\n');
  }
}

export const mlPipeline = new ThreatDetectionPipeline();
