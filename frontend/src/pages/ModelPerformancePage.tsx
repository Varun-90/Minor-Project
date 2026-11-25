import React, { useCallback, useEffect, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { RefreshCw } from 'lucide-react';
import { netshieldApi } from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';
import { persistModelRegistryToFirestore } from '../lib/firebase.ts';
import type { ModelEvaluationMetrics } from '../../../ml/src/pipeline.ts';

function pct(val: number): string {
  return `${(val * 100).toFixed(2)}%`;
}

export function ModelPerformancePage() {
  const { user, isFirebaseBacked } = useAuth();
  const [activeModel, setActiveModel] = useState<ModelEvaluationMetrics | null>(null);
  const [history, setHistory] = useState<ModelEvaluationMetrics[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [nEstimators, setNEstimators] = useState(30);
  const [maxDepth, setMaxDepth] = useState(9);
  const [retraining, setRetraining] = useState(false);

  const loadMetrics = useCallback(async () => {
    setLoading(true);
    try {
      const res = await netshieldApi.getModelMetrics();
      setActiveModel(res.activeModel);
      setHistory(res.history);
      setError(null);
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Failed to load model evaluation metrics.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadMetrics();
  }, [loadMetrics]);

  const handleRetrain = async (e: React.FormEvent) => {
    e.preventDefault();
    setRetraining(true);
    setError(null);
    try {
      const res = await netshieldApi.retrainModel(nEstimators, maxDepth);
      setActiveModel(res.activeModel);
      setHistory(res.history);
      if (isFirebaseBacked && user) {
        await persistModelRegistryToFirestore(user.uid, res.activeModel);
      }
    } catch (err: any) {
      setError(err?.response?.data?.error || 'Retraining failed.');
    } finally {
      setRetraining(false);
    }
  };

  if (loading && !activeModel) {
    return <div className="py-12 text-sm text-neutral-500">Loading model evaluation metrics...</div>;
  }

  if (!activeModel) {
    return (
      <div className="border border-neutral-900 p-6 bg-neutral-50 text-sm text-neutral-950">
        {error || 'No evaluated model found.'}
      </div>
    );
  }

  const cm = activeModel.confusionMatrix;
  const cmTotal = Math.max(cm.tn + cm.fp + cm.fn + cm.tp, 1);

  return (
    <div className="space-y-8">
      <div className="pb-6 border-b border-neutral-200 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Model Performance
          </h1>
          <p className="text-sm text-neutral-600 mt-1">
            {activeModel.algorithm} · Version {activeModel.version} · Dataset {activeModel.dataset} ·
            Held-out Test Split (n={activeModel.testSamples}, zero training leakage)
          </p>
        </div>
        <p className="text-xs font-mono text-neutral-600">
          Artifact: {activeModel.artifactPath}
        </p>
      </div>

      {error && (
        <div className="border border-neutral-900 bg-neutral-100 px-4 py-3 text-sm text-neutral-950">
          {error}
        </div>
      )}

      {/* 5 Core Evaluation Metrics */}
      <section className="grid grid-cols-2 lg:grid-cols-5 border border-neutral-200 divide-y lg:divide-y-0 lg:divide-x divide-neutral-200 bg-white">
        <div className="p-5">
          <p className="text-xs text-neutral-600">Accuracy</p>
          <p className="text-2xl font-semibold font-mono tabular-nums text-neutral-950 mt-1.5">
            {pct(activeModel.accuracy)}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-neutral-600">Precision</p>
          <p className="text-2xl font-semibold font-mono tabular-nums text-neutral-950 mt-1.5">
            {pct(activeModel.precision)}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-neutral-600">Recall</p>
          <p className="text-2xl font-semibold font-mono tabular-nums text-neutral-950 mt-1.5">
            {pct(activeModel.recall)}
          </p>
        </div>
        <div className="p-5">
          <p className="text-xs text-neutral-600">F1-Score</p>
          <p className="text-2xl font-semibold font-mono tabular-nums text-neutral-950 mt-1.5">
            {pct(activeModel.f1Score)}
          </p>
        </div>
        <div className="p-5 bg-neutral-50">
          <p className="text-xs text-neutral-600">False Positive Rate</p>
          <p className="text-2xl font-semibold font-mono tabular-nums text-neutral-950 mt-1.5">
            {pct(activeModel.falsePositiveRate)}
          </p>
        </div>
      </section>

      {/* Confusion Matrix + Feature Importance */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Confusion Matrix */}
        <section className="lg:col-span-5 border border-neutral-200 p-6 bg-white flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-neutral-950">Confusion Matrix</h2>
            <p className="text-xs text-neutral-500 mt-0.5 mb-5">
              Evaluated strictly on {activeModel.testSamples} unseen held-out test records
            </p>

            <div className="grid grid-cols-3 gap-2 text-center text-xs">
              <div />
              <div className="font-mono text-neutral-600 py-1">Pred Normal</div>
              <div className="font-mono text-neutral-600 py-1">Pred Attack</div>

              <div className="font-mono text-neutral-600 flex items-center justify-end pr-2">
                Actual Normal
              </div>
              <div className="border border-neutral-950 bg-neutral-950 text-white p-5">
                <p className="text-[11px] font-mono text-neutral-400">True Negative</p>
                <p className="text-2xl font-mono font-semibold tabular-nums mt-1">{cm.tn}</p>
                <p className="text-[11px] font-mono text-neutral-400 mt-0.5">
                  {((cm.tn / cmTotal) * 100).toFixed(1)}%
                </p>
              </div>
              <div className="border border-neutral-300 bg-neutral-50 text-neutral-950 p-5">
                <p className="text-[11px] font-mono text-neutral-500">False Positive</p>
                <p className="text-2xl font-mono font-semibold tabular-nums mt-1">{cm.fp}</p>
                <p className="text-[11px] font-mono text-neutral-500 mt-0.5">
                  {((cm.fp / cmTotal) * 100).toFixed(1)}%
                </p>
              </div>

              <div className="font-mono text-neutral-600 flex items-center justify-end pr-2">
                Actual Attack
              </div>
              <div className="border border-neutral-300 bg-neutral-50 text-neutral-950 p-5">
                <p className="text-[11px] font-mono text-neutral-500">False Negative</p>
                <p className="text-2xl font-mono font-semibold tabular-nums mt-1">{cm.fn}</p>
                <p className="text-[11px] font-mono text-neutral-500 mt-0.5">
                  {((cm.fn / cmTotal) * 100).toFixed(1)}%
                </p>
              </div>
              <div className="border border-neutral-950 bg-neutral-950 text-white p-5">
                <p className="text-[11px] font-mono text-neutral-400">True Positive</p>
                <p className="text-2xl font-mono font-semibold tabular-nums mt-1">{cm.tp}</p>
                <p className="text-[11px] font-mono text-neutral-400 mt-0.5">
                  {((cm.tp / cmTotal) * 100).toFixed(1)}%
                </p>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-neutral-200 grid grid-cols-2 gap-3 text-xs font-mono text-neutral-600">
            <div>Train Samples: {activeModel.trainSamples}</div>
            <div>Test Samples: {activeModel.testSamples}</div>
            <div>Duplicates Cleaned: {activeModel.cleaningReport.duplicatesRemoved}</div>
            <div>Infinities Capped: {activeModel.cleaningReport.infiniteValuesReplaced}</div>
          </div>
        </section>

        {/* Feature Importances Chart */}
        <section className="lg:col-span-7 border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950">Gini Feature Importance</h2>
          <p className="text-xs text-neutral-500 mt-0.5 mb-5">
            Top 10 CIC-IDS2017 flow features ranked by impurity reduction across {activeModel.nEstimators} decision trees
          </p>
          <div className="h-80 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={activeModel.featureImportances.slice(0, 10).map((f) => ({
                  ...f,
                  pct: Number((f.importance * 100).toFixed(2)),
                }))}
                layout="vertical"
                margin={{ top: 4, right: 20, left: 40, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" horizontal={false} />
                <XAxis
                  type="number"
                  unit="%"
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={{ stroke: '#d4d4d8' }}
                  tickLine={false}
                />
                <YAxis
                  type="category"
                  dataKey="label"
                  width={130}
                  tick={{ fontSize: 11, fill: '#18181b', fontFamily: 'DM Sans' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  formatter={(val: any) => [`${val}%`, 'Importance']}
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #09090b',
                    borderRadius: 0,
                    fontSize: 12,
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Bar dataKey="pct" fill="#18181b" barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </section>
      </div>

      {/* Multiclass Per-Class Report */}
      <section className="border border-neutral-200 bg-white">
        <div className="px-6 py-4 border-b border-neutral-200">
          <h2 className="text-base font-semibold text-neutral-950">
            Multiclass Attack Classification Report
          </h2>
          <p className="text-xs text-neutral-500 mt-0.5">
            Held-out test set precision, recall, and F1-score per attack family
          </p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                <th className="py-3 px-4">Traffic Class</th>
                <th className="py-3 px-4 text-right">Precision</th>
                <th className="py-3 px-4 text-right">Recall</th>
                <th className="py-3 px-4 text-right">F1-Score</th>
                <th className="py-3 px-4 text-right">Support</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-200 text-xs font-mono tabular-nums">
              {activeModel.multiclassMetrics.map((row) => (
                <tr key={row.label} className="hover:bg-neutral-50">
                  <td className="py-2.5 px-4 font-sans font-medium text-neutral-950">{row.label}</td>
                  <td className="py-2.5 px-4 text-right text-neutral-800">{pct(row.precision)}</td>
                  <td className="py-2.5 px-4 text-right text-neutral-800">{pct(row.recall)}</td>
                  <td className="py-2.5 px-4 text-right font-semibold text-neutral-950">{pct(row.f1)}</td>
                  <td className="py-2.5 px-4 text-right text-neutral-600">{row.support}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Retrain Form (Admin) & Evaluation History */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {user?.role === 'admin' && (
          <section className="lg:col-span-4 border border-neutral-200 p-6 bg-white">
            <h2 className="text-base font-semibold text-neutral-950">Train New Model Version</h2>
            <p className="text-xs text-neutral-500 mt-0.5 mb-5">
              Execute a fresh stratified 80/20 split, train a new Random Forest version, and archive metrics.
            </p>
            <form onSubmit={handleRetrain} className="space-y-4">
              <div>
                <label className="block text-xs text-neutral-700 mb-1">
                  Number of Trees (n_estimators)
                </label>
                <input
                  type="number"
                  min={5}
                  max={100}
                  value={nEstimators}
                  onChange={(e) => setNEstimators(Number(e.target.value))}
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <div>
                <label className="block text-xs text-neutral-700 mb-1">Maximum Tree Depth</label>
                <input
                  type="number"
                  min={3}
                  max={20}
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(Number(e.target.value))}
                  className="w-full px-3 py-2 text-sm font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                />
              </div>
              <button
                type="submit"
                disabled={retraining}
                className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 disabled:opacity-40 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${retraining ? 'animate-spin' : ''}`} />
                <span>{retraining ? 'Training & Evaluating...' : 'Retrain & Evaluate Model'}</span>
              </button>
            </form>
          </section>
        )}

        <section
          className={`${user?.role === 'admin' ? 'lg:col-span-8' : 'lg:col-span-12'} border border-neutral-200 bg-white`}
        >
          <div className="px-6 py-4 border-b border-neutral-200">
            <h2 className="text-base font-semibold text-neutral-950">Evaluation History</h2>
            <p className="text-xs text-neutral-500 mt-0.5">
              Registered Random Forest model artifacts and held-out benchmark scores
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-neutral-200 bg-neutral-50 text-xs font-medium text-neutral-600">
                  <th className="py-3 px-4">Version</th>
                  <th className="py-3 px-4">Trees / Depth</th>
                  <th className="py-3 px-4 text-right">Accuracy</th>
                  <th className="py-3 px-4 text-right">Precision</th>
                  <th className="py-3 px-4 text-right">Recall</th>
                  <th className="py-3 px-4 text-right">F1</th>
                  <th className="py-3 px-4">State</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-200 text-xs font-mono tabular-nums">
                {history.map((m) => (
                  <tr key={`${m.version}-${m.trainedAt}`}>
                    <td className="py-3 px-4 font-semibold text-neutral-950">{m.version}</td>
                    <td className="py-3 px-4 text-neutral-600">
                      {m.nEstimators} / {m.maxDepth}
                    </td>
                    <td className="py-3 px-4 text-right text-neutral-900">{pct(m.accuracy)}</td>
                    <td className="py-3 px-4 text-right text-neutral-900">{pct(m.precision)}</td>
                    <td className="py-3 px-4 text-right text-neutral-900">{pct(m.recall)}</td>
                    <td className="py-3 px-4 text-right font-semibold text-neutral-950">
                      {pct(m.f1Score)}
                    </td>
                    <td className="py-3 px-4 font-sans text-xs">
                      {m.isActive ? (
                        <span className="font-semibold text-neutral-950">Active</span>
                      ) : (
                        <span className="text-neutral-500">Archived</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </div>
  );
}
