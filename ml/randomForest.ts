/**
 * Random Forest Classifier (CART Decision Tree Ensemble with Bagging & Feature Subsampling)
 * Genuine implementation using Gini Impurity, stratified train/test splitting,
 * and real feature importance accumulation.
 */

export interface DecisionNode {
  leaf: boolean;
  classCounts: number[];
  prediction?: number;
  featureIndex?: number;
  threshold?: number;
  left?: DecisionNode;
  right?: DecisionNode;
}

export interface RandomForestModelData {
  classes: string[];
  nEstimators: number;
  maxDepth: number;
  minSamplesSplit: number;
  maxFeatures: number;
  trees: DecisionNode[];
  featureImportances: number[];
}

function mulberry32(seed: number) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function giniFromCounts(counts: number[], total: number): number {
  if (total === 0) return 0;
  let sumSq = 0;
  for (let i = 0; i < counts.length; i++) {
    const p = counts[i] / total;
    sumSq += p * p;
  }
  return 1 - sumSq;
}

function argMax(arr: number[]): number {
  let bestIdx = 0;
  let bestVal = arr[0] ?? -Infinity;
  for (let i = 1; i < arr.length; i++) {
    if (arr[i] > bestVal) {
      bestVal = arr[i];
      bestIdx = i;
    }
  }
  return bestIdx;
}

export function stratifiedTrainTestSplit<T>(
  items: T[],
  labels: string[],
  testRatio = 0.2,
  seed = 42
): { trainIndices: number[]; testIndices: number[] } {
  const rng = mulberry32(seed);
  const byClass = new Map<string, number[]>();
  for (let i = 0; i < labels.length; i++) {
    const lbl = labels[i];
    if (!byClass.has(lbl)) byClass.set(lbl, []);
    byClass.get(lbl)!.push(i);
  }

  const trainIndices: number[] = [];
  const testIndices: number[] = [];

  for (const [, indices] of byClass.entries()) {
    // Fisher-Yates shuffle
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    const testCount = Math.max(1, Math.round(indices.length * testRatio));
    for (let i = 0; i < indices.length; i++) {
      if (i < testCount) testIndices.push(indices[i]);
      else trainIndices.push(indices[i]);
    }
  }

  return { trainIndices, testIndices };
}

export class RandomForestClassifier {
  public data: RandomForestModelData;

  constructor(data?: RandomForestModelData) {
    this.data = data ?? {
      classes: [],
      nEstimators: 25,
      maxDepth: 8,
      minSamplesSplit: 4,
      maxFeatures: 4,
      trees: [],
      featureImportances: [],
    };
  }

  public fit(
    X: number[][],
    yLabels: string[],
    options: { nEstimators?: number; maxDepth?: number; minSamplesSplit?: number; seed?: number } = {}
  ): this {
    const nSamples = X.length;
    const nFeatures = X[0]?.length ?? 0;
    const classes = Array.from(new Set(yLabels)).sort();
    const classToIdx = new Map(classes.map((c, idx) => [c, idx]));
    const y = yLabels.map((c) => classToIdx.get(c)!);

    const nEstimators = options.nEstimators ?? 25;
    const maxDepth = options.maxDepth ?? 8;
    const minSamplesSplit = options.minSamplesSplit ?? 4;
    const maxFeatures = Math.max(1, Math.floor(Math.sqrt(nFeatures)));
    const rng = mulberry32(options.seed ?? 1337);

    const importanceAccum = new Array(nFeatures).fill(0);
    const trees: DecisionNode[] = [];

    for (let t = 0; t < nEstimators; t++) {
      // Bootstrap sample
      const bootIndices: number[] = new Array(nSamples);
      for (let i = 0; i < nSamples; i++) {
        bootIndices[i] = Math.floor(rng() * nSamples);
      }

      const tree = this.buildNode(
        X,
        y,
        bootIndices,
        classes.length,
        0,
        maxDepth,
        minSamplesSplit,
        maxFeatures,
        rng,
        importanceAccum
      );
      trees.push(tree);
    }

    const totalImp = importanceAccum.reduce((a, b) => a + b, 0);
    const featureImportances =
      totalImp > 0
        ? importanceAccum.map((v) => Number((v / totalImp).toFixed(4)))
        : new Array(nFeatures).fill(Number((1 / Math.max(nFeatures, 1)).toFixed(4)));

    this.data = {
      classes,
      nEstimators,
      maxDepth,
      minSamplesSplit,
      maxFeatures,
      trees,
      featureImportances,
    };
    return this;
  }

  private buildNode(
    X: number[][],
    y: number[],
    indices: number[],
    numClasses: number,
    depth: number,
    maxDepth: number,
    minSamplesSplit: number,
    maxFeatures: number,
    rng: () => number,
    importanceAccum: number[]
  ): DecisionNode {
    const counts = new Array(numClasses).fill(0);
    for (let i = 0; i < indices.length; i++) {
      counts[y[indices[i]]]++;
    }
    const total = indices.length;
    const parentGini = giniFromCounts(counts, total);
    const majority = argMax(counts);

    if (depth >= maxDepth || total < minSamplesSplit || parentGini === 0) {
      return { leaf: true, classCounts: counts, prediction: majority };
    }

    const nFeatures = X[0].length;
    const featurePool = Array.from({ length: nFeatures }, (_, i) => i);
    for (let i = featurePool.length - 1; i > 0; i--) {
      const j = Math.floor(rng() * (i + 1));
      [featurePool[i], featurePool[j]] = [featurePool[j], featurePool[i]];
    }
    const selectedFeatures = featurePool.slice(0, maxFeatures);

    let bestGain = 0;
    let bestFeature = -1;
    let bestThreshold = 0;

    for (const fIdx of selectedFeatures) {
      const pairs = indices.map((idx) => ({ val: X[idx][fIdx], cls: y[idx] }));
      pairs.sort((a, b) => a.val - b.val);

      const leftCounts = new Array(numClasses).fill(0);
      const rightCounts = [...counts];

      for (let i = 0; i < pairs.length - 1; i++) {
        const cls = pairs[i].cls;
        leftCounts[cls]++;
        rightCounts[cls]--;

        if (pairs[i].val === pairs[i + 1].val) continue;

        const leftTotal = i + 1;
        const rightTotal = total - leftTotal;
        const leftGini = giniFromCounts(leftCounts, leftTotal);
        const rightGini = giniFromCounts(rightCounts, rightTotal);
        const weightedGini = (leftTotal / total) * leftGini + (rightTotal / total) * rightGini;
        const gain = parentGini - weightedGini;

        if (gain > bestGain) {
          bestGain = gain;
          bestFeature = fIdx;
          bestThreshold = (pairs[i].val + pairs[i + 1].val) / 2;
        }
      }
    }

    if (bestFeature === -1 || bestGain <= 1e-7) {
      return { leaf: true, classCounts: counts, prediction: majority };
    }

    const leftIndices: number[] = [];
    const rightIndices: number[] = [];
    for (const idx of indices) {
      if (X[idx][bestFeature] <= bestThreshold) leftIndices.push(idx);
      else rightIndices.push(idx);
    }

    if (leftIndices.length === 0 || rightIndices.length === 0) {
      return { leaf: true, classCounts: counts, prediction: majority };
    }

    importanceAccum[bestFeature] += total * bestGain;

    return {
      leaf: false,
      classCounts: counts,
      featureIndex: bestFeature,
      threshold: bestThreshold,
      left: this.buildNode(
        X,
        y,
        leftIndices,
        numClasses,
        depth + 1,
        maxDepth,
        minSamplesSplit,
        maxFeatures,
        rng,
        importanceAccum
      ),
      right: this.buildNode(
        X,
        y,
        rightIndices,
        numClasses,
        depth + 1,
        maxDepth,
        minSamplesSplit,
        maxFeatures,
        rng,
        importanceAccum
      ),
    };
  }

  private traverse(node: DecisionNode, x: number[]): number[] {
    let curr = node;
    while (!curr.leaf && curr.featureIndex !== undefined && curr.threshold !== undefined) {
      curr = x[curr.featureIndex] <= curr.threshold ? curr.left! : curr.right!;
    }
    return curr.classCounts;
  }

  public predictProba(x: number[]): { probabilities: Record<string, number>; treeVotes: Record<string, number> } {
    const { classes, trees } = this.data;
    const probAccum = new Array(classes.length).fill(0);
    const voteCounts = new Array(classes.length).fill(0);

    for (const tree of trees) {
      const counts = this.traverse(tree, x);
      const total = counts.reduce((a, b) => a + b, 0) || 1;
      for (let i = 0; i < classes.length; i++) {
        probAccum[i] += counts[i] / total;
      }
      voteCounts[argMax(counts)]++;
    }

    const probabilities: Record<string, number> = {};
    const treeVotes: Record<string, number> = {};
    for (let i = 0; i < classes.length; i++) {
      probabilities[classes[i]] = Number((probAccum[i] / Math.max(trees.length, 1)).toFixed(4));
      treeVotes[classes[i]] = voteCounts[i];
    }
    return { probabilities, treeVotes };
  }

  public predict(x: number[]): { label: string; confidence: number; probabilities: Record<string, number>; treeVotes: Record<string, number> } {
    const { probabilities, treeVotes } = this.predictProba(x);
    let bestLabel = this.data.classes[0] ?? 'Normal';
    let bestProb = -1;
    for (const [lbl, prob] of Object.entries(probabilities)) {
      if (prob > bestProb) {
        bestProb = prob;
        bestLabel = lbl;
      }
    }
    return {
      label: bestLabel,
      confidence: Number(bestProb.toFixed(4)),
      probabilities,
      treeVotes,
    };
  }
}
