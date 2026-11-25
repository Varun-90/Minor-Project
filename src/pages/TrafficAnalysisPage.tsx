import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Download, FileSpreadsheet, Play, Upload } from 'lucide-react';
import { CsvImportResponse, DashboardSummary, netshieldApi } from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';
import { persistPredictionToFirestore } from '../lib/firebase.ts';
import type { StoredAlert, StoredNetworkEvent } from '../server/store.ts';

const FLOW_PRESETS: Record<string, Record<string, string | number>> = {
  normal_https: {
    srcIp: '192.168.10.12',
    dstIp: '104.16.132.229',
    srcPort: 54120,
    dstPort: 443,
    protocol: 'TCP',
    flowDuration: 620000,
    totalFwdPackets: 16,
    totalBwdPackets: 22,
    totalLenFwdPackets: 2560,
    totalLenBwdPackets: 19400,
    flowIatMean: 16756,
    synFlagCount: 1,
    ackFlagCount: 28,
    finFlagCount: 1,
    rstFlagCount: 0,
    pshFlagCount: 9,
  },
  ddos_flood: {
    srcIp: '172.16.0.1',
    dstIp: '192.168.10.50',
    srcPort: 49200,
    dstPort: 80,
    protocol: 'TCP',
    flowDuration: 115000,
    totalFwdPackets: 220,
    totalBwdPackets: 2,
    totalLenFwdPackets: 3520,
    totalLenBwdPackets: 64,
    flowIatMean: 520,
    synFlagCount: 20,
    ackFlagCount: 2,
    finFlagCount: 0,
    rstFlagCount: 2,
    pshFlagCount: 0,
  },
  port_scan: {
    srcIp: '185.220.101.42',
    dstIp: '192.168.10.19',
    srcPort: 57810,
    dstPort: 3306,
    protocol: 'TCP',
    flowDuration: 280,
    totalFwdPackets: 2,
    totalBwdPackets: 1,
    totalLenFwdPackets: 8,
    totalLenBwdPackets: 0,
    flowIatMean: 140,
    synFlagCount: 1,
    ackFlagCount: 1,
    finFlagCount: 0,
    rstFlagCount: 2,
    pshFlagCount: 0,
  },
  ssh_bruteforce: {
    srcIp: '172.16.0.1',
    dstIp: '192.168.10.50',
    srcPort: 51904,
    dstPort: 22,
    protocol: 'TCP',
    flowDuration: 6800000,
    totalFwdPackets: 34,
    totalBwdPackets: 30,
    totalLenFwdPackets: 4420,
    totalLenBwdPackets: 4900,
    flowIatMean: 107900,
    synFlagCount: 1,
    ackFlagCount: 48,
    finFlagCount: 1,
    rstFlagCount: 2,
    pshFlagCount: 26,
  },
};

export function TrafficAnalysisPage() {
  const { user, isFirebaseBacked } = useAuth();
  const navigate = useNavigate();

  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [importResult, setImportResult] = useState<CsvImportResponse | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  const [flowForm, setFlowForm] = useState<Record<string, string | number>>(FLOW_PRESETS.ddos_flood);
  const [predicting, setPredicting] = useState(false);
  const [singleResult, setSingleResult] = useState<{
    event: StoredNetworkEvent;
    alert: StoredAlert | null;
  } | null>(null);
  const [predictError, setPredictError] = useState<string | null>(null);

  const canAnalyze = user?.role === 'admin' || user?.role === 'analyst';

  const loadSummary = useCallback(async () => {
    try {
      const data = await netshieldApi.getDashboardSummary();
      setSummary(data);
    } catch {
      // Handled gracefully
    }
  }, []);

  useEffect(() => {
    void loadSummary();
  }, [loadSummary]);

  const handleDownloadSample = async () => {
    try {
      const csvText = await netshieldApi.downloadSampleCsv();
      const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cic_ids2017_sample_flows.csv';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      setUploadError('Unable to download sample CIC-IDS2017 CSV.');
    }
  };

  const handleCsvUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) {
      setUploadError('Select a .csv file first.');
      return;
    }
    if (selectedFile.size > 5 * 1024 * 1024) {
      setUploadError('File exceeds maximum allowed size of 5 MB.');
      return;
    }
    setUploadError(null);
    setUploading(true);
    try {
      const res = await netshieldApi.importCsvFile(selectedFile);
      setImportResult(res);
      setSelectedFile(null);

      // Persist analyzed batch records to Firestore when using Firebase Auth
      if (isFirebaseBacked && user) {
        const alertByEventId = new Map(res.alerts.map((a) => [a.eventId, a]));
        for (const evt of res.events.slice(0, 40)) {
          await persistPredictionToFirestore(user.uid, evt, alertByEventId.get(evt.id) ?? null);
        }
      }
      await loadSummary();
    } catch (err: any) {
      setUploadError(err?.response?.data?.error || err?.message || 'CSV analysis failed.');
    } finally {
      setUploading(false);
    }
  };

  const handleSinglePredict = async (e: React.FormEvent) => {
    e.preventDefault();
    setPredictError(null);
    setPredicting(true);
    try {
      const res = await netshieldApi.submitSinglePrediction(flowForm);
      setSingleResult(res);
      if (isFirebaseBacked && user) {
        await persistPredictionToFirestore(user.uid, res.event, res.alert);
      }
      await loadSummary();
    } catch (err: any) {
      setPredictError(err?.response?.data?.error || 'Single-flow prediction failed.');
    } finally {
      setPredicting(false);
    }
  };

  const normalVsAttackData = summary
    ? [
        { category: 'Normal Traffic', count: summary.normalCount },
        { category: 'Attack Traffic', count: summary.suspiciousCount },
      ]
    : [];

  return (
    <div className="space-y-8">
      <div className="pb-6 border-b border-neutral-200 flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-neutral-950">
            Traffic Analysis
          </h1>
          <p className="text-sm text-neutral-600 mt-1">
            Offline CIC-IDS2017 CSV batch ingestion and single network-flow classification (detection-only mode; not live packet capture).
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleDownloadSample()}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium border border-neutral-950 bg-white text-neutral-950 hover:bg-neutral-100 transition-colors cursor-pointer whitespace-nowrap shrink-0"
        >
          <Download className="w-3.5 h-3.5" />
          <span>Download Sample CIC-IDS2017 CSV</span>
        </button>
      </div>

      {/* CSV Upload + Single Flow Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Batch CSV Upload */}
        <section className="lg:col-span-5 border border-neutral-200 p-6 bg-white flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <FileSpreadsheet className="w-4 h-4 text-neutral-900" />
              <h2 className="text-base font-semibold text-neutral-950">CSV Flow Batch Upload</h2>
            </div>
            <p className="text-xs text-neutral-600 mb-5">
              Upload CIC-IDS2017 network-flow CSV files (max 5 MB, up to 500 records per batch). Duplicates, NaNs, and Infinity values are automatically cleaned before inference.
            </p>

            {uploadError && (
              <div className="mb-4 border border-neutral-900 bg-neutral-100 px-3 py-2 text-xs text-neutral-950">
                {uploadError}
              </div>
            )}

            <form onSubmit={handleCsvUpload} className="space-y-4">
              <label className="block border border-dashed border-neutral-400 p-6 text-center hover:border-neutral-950 transition-colors cursor-pointer bg-neutral-50">
                <Upload className="w-5 h-5 text-neutral-700 mx-auto mb-2" />
                <span className="block text-sm font-medium text-neutral-900">
                  {selectedFile ? selectedFile.name : 'Choose a CIC-IDS2017 CSV file'}
                </span>
                <span className="block text-xs text-neutral-500 mt-1">
                  {selectedFile
                    ? `${(selectedFile.size / 1024).toFixed(1)} KB selected`
                    : 'Accepted format: .csv · Max size 5 MB'}
                </span>
                <input
                  type="file"
                  accept=".csv,text/csv"
                  disabled={!canAnalyze}
                  onChange={(e) => {
                    setSelectedFile(e.target.files?.[0] ?? null);
                    setUploadError(null);
                  }}
                  className="sr-only"
                />
              </label>

              <button
                type="submit"
                disabled={uploading || !selectedFile || !canAnalyze}
                className="w-full px-4 py-2.5 text-sm font-medium bg-neutral-950 text-white hover:bg-neutral-800 disabled:opacity-40 transition-colors cursor-pointer"
              >
                {uploading ? 'Cleaning & Classifying Flows...' : 'Upload & Run Random Forest Analysis'}
              </button>
            </form>
          </div>

          {importResult && (
            <div className="mt-6 pt-5 border-t border-neutral-200 space-y-2 text-xs">
              <p className="font-semibold text-neutral-950">
                Batch Completed: {importResult.batchName}
              </p>
              <div className="grid grid-cols-2 gap-2 font-mono tabular-nums text-neutral-700">
                <div>Imported: {importResult.importedCount}</div>
                <div>Suspicious: {importResult.suspiciousCount}</div>
                <div>Normal: {importResult.normalCount}</div>
                <div>Duplicates Removed: {importResult.cleaningReport.duplicatesRemoved}</div>
                <div>NaNs Imputed: {importResult.cleaningReport.missingValuesImputed}</div>
                <div>Infinities Capped: {importResult.cleaningReport.infiniteValuesReplaced}</div>
              </div>
              <button
                type="button"
                onClick={() => navigate('/monitoring')}
                className="mt-2 inline-block text-xs font-medium text-neutral-950 underline underline-offset-4 cursor-pointer"
              >
                Inspect Imported Events →
              </button>
            </div>
          )}
        </section>

        {/* Single Network-Flow Submission */}
        <section className="lg:col-span-7 border border-neutral-200 p-6 bg-white">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-5">
            <div>
              <h2 className="text-base font-semibold text-neutral-950">Single Flow Inspector</h2>
              <p className="text-xs text-neutral-500 mt-0.5">
                Submit a single flow record directly to POST /api/v1/predictions
              </p>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              {[
                { key: 'normal_https', label: 'Benign HTTPS' },
                { key: 'ddos_flood', label: 'DDoS' },
                { key: 'port_scan', label: 'PortScan' },
                { key: 'ssh_bruteforce', label: 'SSH Brute' },
              ].map((preset) => (
                <button
                  key={preset.key}
                  type="button"
                  onClick={() => setFlowForm(FLOW_PRESETS[preset.key])}
                  className="px-2.5 py-1 text-xs border border-neutral-300 text-neutral-800 hover:bg-neutral-950 hover:text-white transition-colors cursor-pointer whitespace-nowrap"
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          {predictError && (
            <div className="mb-4 border border-neutral-900 bg-neutral-100 px-3 py-2 text-xs text-neutral-950">
              {predictError}
            </div>
          )}

          <form onSubmit={handleSinglePredict} className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { name: 'srcIp', label: 'Source IP', type: 'text' },
                { name: 'dstIp', label: 'Destination IP', type: 'text' },
                { name: 'dstPort', label: 'Dest Port', type: 'number' },
                { name: 'protocol', label: 'Protocol', type: 'select' },
                { name: 'flowDuration', label: 'Duration (us)', type: 'number' },
                { name: 'totalFwdPackets', label: 'Fwd Packets', type: 'number' },
                { name: 'totalBwdPackets', label: 'Bwd Packets', type: 'number' },
                { name: 'totalLenFwdPackets', label: 'Fwd Bytes', type: 'number' },
                { name: 'totalLenBwdPackets', label: 'Bwd Bytes', type: 'number' },
                { name: 'synFlagCount', label: 'SYN Flags', type: 'number' },
                { name: 'ackFlagCount', label: 'ACK Flags', type: 'number' },
                { name: 'rstFlagCount', label: 'RST Flags', type: 'number' },
              ].map((field) => (
                <div key={field.name}>
                  <label className="block text-xs text-neutral-600 mb-1">{field.label}</label>
                  {field.type === 'select' ? (
                    <select
                      value={String(flowForm[field.name] ?? 'TCP')}
                      onChange={(e) => setFlowForm((f) => ({ ...f, [field.name]: e.target.value }))}
                      className="w-full px-2.5 py-1.5 text-xs font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                    >
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="ICMP">ICMP</option>
                    </select>
                  ) : (
                    <input
                      type={field.type}
                      value={flowForm[field.name] ?? ''}
                      onChange={(e) =>
                        setFlowForm((f) => ({
                          ...f,
                          [field.name]: field.type === 'number' ? Number(e.target.value) : e.target.value,
                        }))
                      }
                      className="w-full px-2.5 py-1.5 text-xs font-mono border border-neutral-300 bg-white focus:outline-none focus:border-neutral-950"
                    />
                  )}
                </div>
              ))}
            </div>

            <div className="flex items-center justify-between gap-4 pt-2">
              <button
                type="submit"
                disabled={predicting || !canAnalyze}
                className="inline-flex items-center gap-2 px-4 py-2 text-xs font-medium bg-neutral-950 text-white hover:bg-neutral-800 disabled:opacity-40 cursor-pointer whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5" />
                <span>{predicting ? 'Classifying...' : 'Run Flow Prediction'}</span>
              </button>

              {singleResult && (
                <div className="text-xs font-mono text-neutral-900">
                  Result:{' '}
                  <span className="font-semibold">
                    {singleResult.event.prediction} ({singleResult.event.attackType})
                  </span>{' '}
                  · Score {(singleResult.event.score * 100).toFixed(1)}% · Severity{' '}
                  {singleResult.event.severity}
                  <button
                    type="button"
                    onClick={() => navigate(`/monitoring/${singleResult.event.id}`)}
                    className="ml-3 underline underline-offset-4 cursor-pointer"
                  >
                    Inspect
                  </button>
                </div>
              )}
            </div>
          </form>
        </section>
      </div>

      {/* Traffic Statistics & Charts */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-6 border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950 mb-1">Protocol Distribution</h2>
          <p className="text-xs text-neutral-500 mb-5">
            Analyzed flow counts grouped by transport protocol
          </p>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={summary?.protocolDistribution ?? []} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" vertical={false} />
                <XAxis
                  dataKey="protocol"
                  tick={{ fontSize: 11, fill: '#18181b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={{ stroke: '#d4d4d8' }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #09090b',
                    borderRadius: 0,
                    fontSize: 12,
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Bar dataKey="count" name="Flows" fill="#18181b" barSize={36} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-6 border border-neutral-200 p-6 bg-white">
          <h2 className="text-base font-semibold text-neutral-950 mb-1">Normal vs. Attack Traffic</h2>
          <p className="text-xs text-neutral-500 mb-5">
            Aggregate packet volume: {summary?.totalPackets.toLocaleString() ?? 0} packets ·{' '}
            {summary?.totalBytes.toLocaleString() ?? 0} bytes inspected
          </p>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={normalVsAttackData} margin={{ top: 8, right: 16, left: -12, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e4e4e7" vertical={false} />
                <XAxis
                  dataKey="category"
                  tick={{ fontSize: 11, fill: '#18181b', fontFamily: 'DM Sans' }}
                  axisLine={{ stroke: '#d4d4d8' }}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  tick={{ fontSize: 11, fill: '#52525b', fontFamily: 'IBM Plex Mono' }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #09090b',
                    borderRadius: 0,
                    fontSize: 12,
                    fontFamily: 'IBM Plex Mono',
                  }}
                />
                <Bar dataKey="count" name="Flows" fill="#09090b" barSize={56} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>
    </div>
  );
}
