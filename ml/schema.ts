/**
 * Shared CIC-IDS2017 Feature Schema & Preprocessing Utilities
 * Guarantees identical feature ordering and encoding between training and inference.
 */

export const FEATURE_NAMES = [
  'dstPort',
  'protocolCode',
  'flowDuration',
  'totalFwdPackets',
  'totalBwdPackets',
  'totalLenFwdPackets',
  'totalLenBwdPackets',
  'fwdPacketLenMean',
  'bwdPacketLenMean',
  'flowBytesPerSec',
  'flowPacketsPerSec',
  'flowIatMean',
  'synFlagCount',
  'ackFlagCount',
  'finFlagCount',
  'rstFlagCount',
  'pshFlagCount',
] as const;

export type FeatureName = (typeof FEATURE_NAMES)[number];

export const FEATURE_LABELS: Record<FeatureName, string> = {
  dstPort: 'Destination Port',
  protocolCode: 'Protocol Code',
  flowDuration: 'Flow Duration (us)',
  totalFwdPackets: 'Total Fwd Packets',
  totalBwdPackets: 'Total Bwd Packets',
  totalLenFwdPackets: 'Total Length Fwd (B)',
  totalLenBwdPackets: 'Total Length Bwd (B)',
  fwdPacketLenMean: 'Fwd Packet Len Mean',
  bwdPacketLenMean: 'Bwd Packet Len Mean',
  flowBytesPerSec: 'Flow Bytes/s',
  flowPacketsPerSec: 'Flow Packets/s',
  flowIatMean: 'Flow IAT Mean (us)',
  synFlagCount: 'SYN Flag Count',
  ackFlagCount: 'ACK Flag Count',
  finFlagCount: 'FIN Flag Count',
  rstFlagCount: 'RST Flag Count',
  pshFlagCount: 'PSH Flag Count',
};

export type ProtocolName = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
export type BinaryLabel = 'Normal' | 'Attack';
export type SeverityLevel = 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
export type AlertStatus = 'Open' | 'Investigating' | 'Resolved';

export interface RawFlowRecord {
  eventTime?: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number | string;
  dstPort?: number | string;
  protocol?: string | number;
  flowDuration?: number | string;
  totalFwdPackets?: number | string;
  totalBwdPackets?: number | string;
  totalLenFwdPackets?: number | string;
  totalLenBwdPackets?: number | string;
  fwdPacketLenMean?: number | string;
  bwdPacketLenMean?: number | string;
  flowBytesPerSec?: number | string;
  flowPacketsPerSec?: number | string;
  flowIatMean?: number | string;
  synFlagCount?: number | string;
  ackFlagCount?: number | string;
  finFlagCount?: number | string;
  rstFlagCount?: number | string;
  pshFlagCount?: number | string;
  label?: string;
}

export interface CleanedFlowRecord {
  eventTime: string;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: ProtocolName;
  features: number[];
  rawFeatureMap: Record<FeatureName, number>;
  label?: string;
}

export interface PreprocessorStats {
  medians: number[];
  maxCaps: number[];
  featureNames: readonly FeatureName[];
}

export interface CleaningReport {
  totalRawRows: number;
  duplicatesRemoved: number;
  missingValuesImputed: number;
  infiniteValuesReplaced: number;
  validRowsRetained: number;
}

export function normalizeProtocol(input: string | number | undefined): {
  name: ProtocolName;
  code: number;
} {
  if (typeof input === 'number' && Number.isFinite(input)) {
    if (input === 6) return { name: 'TCP', code: 6 };
    if (input === 17) return { name: 'UDP', code: 17 };
    if (input === 1) return { name: 'ICMP', code: 1 };
    return { name: 'OTHER', code: 0 };
  }
  const s = String(input ?? 'TCP').trim().toUpperCase();
  if (s === 'TCP' || s === '6') return { name: 'TCP', code: 6 };
  if (s === 'UDP' || s === '17') return { name: 'UDP', code: 17 };
  if (s === 'ICMP' || s === '1') return { name: 'ICMP', code: 1 };
  return { name: 'OTHER', code: 0 };
}

export function parseNumeric(val: unknown): number {
  if (val === null || val === undefined || val === '') return Number.NaN;
  if (typeof val === 'number') return val;
  const trimmed = String(val).trim();
  if (trimmed === '' || trimmed.toLowerCase() === 'nan' || trimmed.toLowerCase() === 'null') {
    return Number.NaN;
  }
  if (trimmed.toLowerCase() === 'infinity' || trimmed.toLowerCase() === 'inf') {
    return Number.POSITIVE_INFINITY;
  }
  if (trimmed.toLowerCase() === '-infinity' || trimmed.toLowerCase() === '-inf') {
    return Number.NEGATIVE_INFINITY;
  }
  const parsed = Number(trimmed);
  return Number.isNaN(parsed) ? Number.NaN : parsed;
}

/**
 * Maps CIC-IDS2017 official CSV column headers or snake_case/camelCase keys into a RawFlowRecord.
 */
export function mapCsvRowToRawFlow(row: Record<string, string>): RawFlowRecord {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(row)) {
    const k = key.trim().toLowerCase().replace(/[^a-z0-9]/g, '');
    normalized[k] = value?.trim() ?? '';
  }

  const pick = (...aliases: string[]): string | undefined => {
    for (const alias of aliases) {
      if (normalized[alias] !== undefined && normalized[alias] !== '') {
        return normalized[alias];
      }
    }
    return undefined;
  };

  return {
    eventTime: pick('timestamp', 'eventtime', 'time'),
    srcIp: pick('sourceip', 'srcip', 'idorigih', 'origip'),
    dstIp: pick('destinationip', 'dstip', 'idresph', 'respip'),
    srcPort: pick('sourceport', 'srcport', 'idorigp'),
    dstPort: pick('destinationport', 'dstport', 'idrespp', 'dport'),
    protocol: pick('protocol', 'proto'),
    flowDuration: pick('flowduration', 'duration'),
    totalFwdPackets: pick('totalfwdpackets', 'totfwdpkts', 'fwdpackets', 'origpkts'),
    totalBwdPackets: pick('totalbackwardpackets', 'totalbwdpackets', 'totbwdpkts', 'bwdpackets', 'resppkts'),
    totalLenFwdPackets: pick('totallengthoffwdpackets', 'totallengthfwdpackets', 'totlenfwdpkts', 'origbytes'),
    totalLenBwdPackets: pick('totallengthofbwdpackets', 'totallengthbwdpackets', 'totlenbwdpkts', 'respbytes'),
    fwdPacketLenMean: pick('fwdpacketlengthmean', 'fwdpktlenmean'),
    bwdPacketLenMean: pick('bwdpacketlengthmean', 'bwdpktlenmean'),
    flowBytesPerSec: pick('flowbytess', 'flowbytespersec', 'bytespersec'),
    flowPacketsPerSec: pick('flowpacketss', 'flowpacketspersec', 'packetspersec'),
    flowIatMean: pick('flowiatmean', 'iatmean'),
    synFlagCount: pick('synflagcount', 'synflags', 'syn'),
    ackFlagCount: pick('ackflagcount', 'ackflags', 'ack'),
    finFlagCount: pick('finflagcount', 'finflags', 'fin'),
    rstFlagCount: pick('rstflagcount', 'rstflags', 'rst'),
    pshFlagCount: pick('pshflagcount', 'pshflags', 'psh'),
    label: pick('label', 'attackcat', 'class'),
  };
}

export function extractRawVector(raw: RawFlowRecord): number[] {
  const proto = normalizeProtocol(raw.protocol);
  const fwdPkts = parseNumeric(raw.totalFwdPackets);
  const bwdPkts = parseNumeric(raw.totalBwdPackets);
  const fwdLen = parseNumeric(raw.totalLenFwdPackets);
  const bwdLen = parseNumeric(raw.totalLenBwdPackets);
  const duration = parseNumeric(raw.flowDuration);

  let fwdMean = parseNumeric(raw.fwdPacketLenMean);
  if (Number.isNaN(fwdMean) && Number.isFinite(fwdLen) && Number.isFinite(fwdPkts) && fwdPkts > 0) {
    fwdMean = fwdLen / fwdPkts;
  }
  let bwdMean = parseNumeric(raw.bwdPacketLenMean);
  if (Number.isNaN(bwdMean) && Number.isFinite(bwdLen) && Number.isFinite(bwdPkts) && bwdPkts > 0) {
    bwdMean = bwdLen / bwdPkts;
  }

  let bytesPerSec = parseNumeric(raw.flowBytesPerSec);
  if (
    Number.isNaN(bytesPerSec) &&
    Number.isFinite(duration) &&
    duration > 0 &&
    Number.isFinite(fwdLen) &&
    Number.isFinite(bwdLen)
  ) {
    bytesPerSec = ((fwdLen + bwdLen) * 1_000_000) / duration;
  }

  let pktsPerSec = parseNumeric(raw.flowPacketsPerSec);
  if (
    Number.isNaN(pktsPerSec) &&
    Number.isFinite(duration) &&
    duration > 0 &&
    Number.isFinite(fwdPkts) &&
    Number.isFinite(bwdPkts)
  ) {
    pktsPerSec = ((fwdPkts + bwdPkts) * 1_000_000) / duration;
  }

  return [
    parseNumeric(raw.dstPort),
    proto.code,
    duration,
    fwdPkts,
    bwdPkts,
    fwdLen,
    bwdLen,
    fwdMean,
    bwdMean,
    bytesPerSec,
    pktsPerSec,
    parseNumeric(raw.flowIatMean),
    parseNumeric(raw.synFlagCount ?? 0),
    parseNumeric(raw.ackFlagCount ?? 0),
    parseNumeric(raw.finFlagCount ?? 0),
    parseNumeric(raw.rstFlagCount ?? 0),
    parseNumeric(raw.pshFlagCount ?? 0),
  ];
}

/**
 * Fits median imputation and finite upper bounds strictly on the training split (zero data leakage).
 */
export function fitPreprocessor(rawVectors: number[][]): PreprocessorStats {
  const numFeatures = FEATURE_NAMES.length;
  const medians: number[] = new Array(numFeatures).fill(0);
  const maxCaps: number[] = new Array(numFeatures).fill(0);

  for (let col = 0; col < numFeatures; col++) {
    const finiteValues: number[] = [];
    for (let i = 0; i < rawVectors.length; i++) {
      const v = rawVectors[i][col];
      if (Number.isFinite(v)) {
        finiteValues.push(v);
      }
    }
    if (finiteValues.length === 0) {
      medians[col] = 0;
      maxCaps[col] = 1;
      continue;
    }
    finiteValues.sort((a, b) => a - b);
    const mid = Math.floor(finiteValues.length / 2);
    medians[col] =
      finiteValues.length % 2 === 0
        ? (finiteValues[mid - 1] + finiteValues[mid]) / 2
        : finiteValues[mid];
    // 99.5th percentile cap for replacing +Infinity values
    const p99Idx = Math.min(finiteValues.length - 1, Math.floor(finiteValues.length * 0.995));
    maxCaps[col] = Math.max(finiteValues[p99Idx], 1);
  }

  return { medians, maxCaps, featureNames: FEATURE_NAMES };
}

export function transformVector(
  rawVec: number[],
  stats: PreprocessorStats
): { vector: number[]; missingCount: number; infiniteCount: number } {
  let missingCount = 0;
  let infiniteCount = 0;
  const vector = rawVec.map((val, idx) => {
    if (Number.isNaN(val)) {
      missingCount++;
      return stats.medians[idx];
    }
    if (!Number.isFinite(val)) {
      infiniteCount++;
      return val > 0 ? stats.maxCaps[idx] : 0;
    }
    return Math.max(0, val);
  });
  return { vector, missingCount, infiniteCount };
}

export function deduplicateRawFlows(records: RawFlowRecord[]): {
  unique: RawFlowRecord[];
  duplicatesRemoved: number;
} {
  const seen = new Set<string>();
  const unique: RawFlowRecord[] = [];
  let duplicatesRemoved = 0;

  for (const r of records) {
    const sig = [
      r.srcIp ?? '',
      r.dstIp ?? '',
      r.srcPort ?? '',
      r.dstPort ?? '',
      r.protocol ?? '',
      r.flowDuration ?? '',
      r.totalFwdPackets ?? '',
      r.totalBwdPackets ?? '',
      r.totalLenFwdPackets ?? '',
      r.totalLenBwdPackets ?? '',
      r.synFlagCount ?? '',
      r.ackFlagCount ?? '',
      r.label ?? '',
    ].join('|');
    if (seen.has(sig)) {
      duplicatesRemoved++;
      continue;
    }
    seen.add(sig);
    unique.push(r);
  }
  return { unique, duplicatesRemoved };
}

export function parseCsvText(csvText: string): Record<string, string>[] {
  const lines = csvText
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .filter((l) => l.trim().length > 0);
  if (lines.length < 2) return [];

  const splitCsvLine = (line: string): string[] => {
    const result: string[] = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (ch === ',' && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += ch;
      }
    }
    result.push(current.trim());
    return result;
  };

  const headers = splitCsvLine(lines[0]);
  const rows: Record<string, string>[] = [];

  for (let i = 1; i < lines.length; i++) {
    const cols = splitCsvLine(lines[i]);
    if (cols.length < 3) continue;
    const obj: Record<string, string> = {};
    for (let j = 0; j < headers.length; j++) {
      obj[headers[j]] = cols[j] ?? '';
    }
    rows.push(obj);
  }
  return rows;
}
