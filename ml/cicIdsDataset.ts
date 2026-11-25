/**
 * CIC-IDS2017 Benchmark Network-Flow Dataset Builder
 * Models authentic CIC-IDS2017 feature profiles across BENIGN and 6 attack families
 * (DDoS, PortScan, DoS Hulk, Brute Force, Botnet, Web Attack) with realistic variance
 * and borderline overlap so model evaluation produces genuine ML metrics.
 */

import { RawFlowRecord } from './schema.ts';

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

function randRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min);
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(randRange(rng, min, max + 0.999));
}

function pickOne<T>(rng: () => number, items: T[]): T {
  return items[Math.floor(rng() * items.length)];
}

export function buildCicIds2017BenchmarkDataset(seed = 20170707): RawFlowRecord[] {
  const rng = mulberry32(seed);
  const records: RawFlowRecord[] = [];
  const baseTs = new Date('2026-11-24T08:00:00Z').getTime();

  const internalIps = [
    '192.168.10.5',
    '192.168.10.8',
    '192.168.10.9',
    '192.168.10.12',
    '192.168.10.14',
    '192.168.10.15',
    '192.168.10.19',
    '192.168.10.25',
    '192.168.10.50',
  ];
  const externalBenignIps = [
    '104.16.132.229',
    '172.217.10.46',
    '52.94.236.248',
    '151.101.1.69',
    '13.107.42.14',
    '8.8.8.8',
    '1.1.1.1',
  ];
  const attackerIps = [
    '172.16.0.1',
    '205.174.165.73',
    '185.220.101.42',
    '45.155.205.91',
    '198.51.100.24',
  ];

  const makeTime = (idx: number) => new Date(baseTs + idx * 14000).toISOString();

  // 1. BENIGN traffic (640 flows: HTTPS, HTTP, DNS, SSH admin, NTP, SMB, heavy file transfer)
  for (let i = 0; i < 640; i++) {
    const profile = rng();
    let dstPort = 443;
    let protocol: 'TCP' | 'UDP' | 'ICMP' = 'TCP';
    let duration = randInt(rng, 25000, 4200000);
    let fwdPkts = randInt(rng, 4, 42);
    let bwdPkts = randInt(rng, 4, 56);
    let fwdMean = randRange(rng, 52, 420);
    let bwdMean = randRange(rng, 120, 1280);
    let syn = 1;
    let ack = randInt(rng, 4, 48);
    let fin = randInt(rng, 1, 2);
    let rst = rng() < 0.08 ? 1 : 0;
    let psh = randInt(rng, 2, 16);

    if (profile < 0.24) {
      // DNS / UDP normal lookup
      dstPort = pickOne(rng, [53, 123, 443]);
      protocol = 'UDP';
      duration = randInt(rng, 180, 95000);
      fwdPkts = randInt(rng, 1, 4);
      bwdPkts = randInt(rng, 1, 4);
      fwdMean = randRange(rng, 38, 92);
      bwdMean = randRange(rng, 64, 240);
      syn = 0;
      ack = 0;
      fin = 0;
      rst = 0;
      psh = 0;
    } else if (profile < 0.36) {
      // Benign bursty CDN / API fetch (creates realistic overlap with DoS edge cases)
      dstPort = pickOne(rng, [80, 443, 8080]);
      duration = randInt(rng, 12000, 380000);
      fwdPkts = randInt(rng, 12, 85);
      bwdPkts = randInt(rng, 18, 120);
      fwdMean = randRange(rng, 64, 340);
      bwdMean = randRange(rng, 480, 1440);
      syn = 1;
      ack = randInt(rng, 16, 110);
      fin = 1;
      psh = randInt(rng, 4, 24);
    } else if (profile < 0.44) {
      // Benign SSH or internal admin session
      dstPort = pickOne(rng, [22, 445, 3306]);
      duration = randInt(rng, 450000, 14000000);
      fwdPkts = randInt(rng, 10, 48);
      bwdPkts = randInt(rng, 10, 52);
      fwdMean = randRange(rng, 68, 220);
      bwdMean = randRange(rng, 96, 460);
      syn = 1;
      ack = randInt(rng, 14, 64);
      fin = 1;
      psh = randInt(rng, 6, 28);
    } else if (profile < 0.48) {
      // Benign short TCP health check / ping
      dstPort = pickOne(rng, [80, 443, 8443]);
      duration = randInt(rng, 450, 8500);
      fwdPkts = randInt(rng, 2, 5);
      bwdPkts = randInt(rng, 2, 4);
      fwdMean = randRange(rng, 40, 110);
      bwdMean = randRange(rng, 40, 180);
      syn = 1;
      ack = randInt(rng, 2, 5);
      fin = 1;
      rst = rng() < 0.25 ? 1 : 0;
      psh = 1;
    }

    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, internalIps),
      dstIp: pickOne(rng, externalBenignIps),
      srcPort: randInt(rng, 32768, 65000),
      dstPort,
      protocol,
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: syn,
      ackFlagCount: ack,
      finFlagCount: fin,
      rstFlagCount: rst,
      pshFlagCount: psh,
      label: 'BENIGN',
    });
  }

  // 2. DDoS (LOIC / Volumetric HTTP/SYN Flood) - 110 flows
  for (let i = 0; i < 110; i++) {
    const duration = randInt(rng, 8000, 620000);
    const fwdPkts = randInt(rng, 48, 320);
    const bwdPkts = randInt(rng, 0, 12);
    const fwdMean = randRange(rng, 6, 48);
    const bwdMean = bwdPkts > 0 ? randRange(rng, 12, 110) : 0;
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, attackerIps),
      dstIp: '192.168.10.50',
      srcPort: randInt(rng, 1024, 65000),
      dstPort: pickOne(rng, [80, 443]),
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: randInt(rng, 3, 28),
      ackFlagCount: randInt(rng, 1, 10),
      finFlagCount: 0,
      rstFlagCount: randInt(rng, 0, 4),
      pshFlagCount: randInt(rng, 0, 3),
      label: 'DDoS',
    });
  }

  // 3. PortScan (SYN/RST rapid reconnaissance probes) - 105 flows
  for (let i = 0; i < 105; i++) {
    const duration = randInt(rng, 15, 2200);
    const fwdPkts = randInt(rng, 1, 3);
    const bwdPkts = randInt(rng, 0, 2);
    const fwdMean = randRange(rng, 0, 24);
    const bwdMean = bwdPkts > 0 ? randRange(rng, 0, 18) : 0;
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.00001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, attackerIps),
      dstIp: pickOne(rng, internalIps),
      srcPort: randInt(rng, 40000, 65000),
      dstPort: pickOne(rng, [21, 22, 23, 25, 110, 139, 445, 1433, 3306, 3389, 5432, 8080, 8443]),
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: 1,
      ackFlagCount: bwdPkts > 0 ? 1 : 0,
      finFlagCount: 0,
      rstFlagCount: randInt(rng, 1, 2),
      pshFlagCount: 0,
      label: 'PortScan',
    });
  }

  // 4. DoS Hulk (High-volume HTTP GET exhaustion) - 90 flows
  for (let i = 0; i < 90; i++) {
    const duration = randInt(rng, 1200000, 95000000);
    const fwdPkts = randInt(rng, 6, 22);
    const bwdPkts = randInt(rng, 5, 16);
    const fwdMean = randRange(rng, 160, 480);
    const bwdMean = randRange(rng, 1100, 3600);
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, attackerIps),
      dstIp: '192.168.10.50',
      srcPort: randInt(rng, 32000, 64000),
      dstPort: 80,
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: 1,
      ackFlagCount: randInt(rng, 4, 14),
      finFlagCount: 1,
      rstFlagCount: 0,
      pshFlagCount: randInt(rng, 1, 4),
      label: 'DoS Hulk',
    });
  }

  // 5. Brute Force (SSH-Patator / FTP-Patator) - 70 flows
  for (let i = 0; i < 70; i++) {
    const duration = randInt(rng, 1800000, 12500000);
    const fwdPkts = randInt(rng, 16, 46);
    const bwdPkts = randInt(rng, 14, 42);
    const fwdMean = randRange(rng, 85, 175);
    const bwdMean = randRange(rng, 95, 220);
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, attackerIps),
      dstIp: '192.168.10.50',
      srcPort: randInt(rng, 35000, 62000),
      dstPort: pickOne(rng, [21, 22]),
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: 1,
      ackFlagCount: randInt(rng, 22, 65),
      finFlagCount: 1,
      rstFlagCount: randInt(rng, 1, 3),
      pshFlagCount: randInt(rng, 14, 38),
      label: 'Brute Force',
    });
  }

  // 6. Botnet (ARES C2 periodic beaconing) - 45 flows
  for (let i = 0; i < 45; i++) {
    const duration = randInt(rng, 65000, 520000);
    const fwdPkts = randInt(rng, 4, 11);
    const bwdPkts = randInt(rng, 3, 9);
    const fwdMean = randRange(rng, 32, 96);
    const bwdMean = randRange(rng, 28, 84);
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, internalIps),
      dstIp: '205.174.165.73',
      srcPort: randInt(rng, 49152, 65000),
      dstPort: 8080,
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: 1,
      ackFlagCount: randInt(rng, 5, 14),
      finFlagCount: 1,
      rstFlagCount: 0,
      pshFlagCount: randInt(rng, 3, 8),
      label: 'Botnet',
    });
  }

  // 7. Web Attack (SQLi / XSS payload bursts) - 40 flows
  for (let i = 0; i < 40; i++) {
    const duration = randInt(rng, 4800000, 22000000);
    const fwdPkts = randInt(rng, 18, 60);
    const bwdPkts = randInt(rng, 12, 42);
    const fwdMean = randRange(rng, 420, 980);
    const bwdMean = randRange(rng, 180, 620);
    const fwdLen = Math.round(fwdPkts * fwdMean);
    const bwdLen = Math.round(bwdPkts * bwdMean);
    const totalPkts = fwdPkts + bwdPkts;
    const sec = Math.max(duration / 1_000_000, 0.0001);

    records.push({
      eventTime: makeTime(records.length),
      srcIp: pickOne(rng, attackerIps),
      dstIp: '192.168.10.50',
      srcPort: randInt(rng, 42000, 62000),
      dstPort: pickOne(rng, [80, 443]),
      protocol: 'TCP',
      flowDuration: duration,
      totalFwdPackets: fwdPkts,
      totalBwdPackets: bwdPkts,
      totalLenFwdPackets: fwdLen,
      totalLenBwdPackets: bwdLen,
      fwdPacketLenMean: Number(fwdMean.toFixed(2)),
      bwdPacketLenMean: Number(bwdMean.toFixed(2)),
      flowBytesPerSec: Number(((fwdLen + bwdLen) / sec).toFixed(2)),
      flowPacketsPerSec: Number((totalPkts / sec).toFixed(2)),
      flowIatMean: Number((duration / Math.max(totalPkts - 1, 1)).toFixed(2)),
      synFlagCount: 1,
      ackFlagCount: randInt(rng, 18, 56),
      finFlagCount: 1,
      rstFlagCount: 0,
      pshFlagCount: randInt(rng, 12, 34),
      label: 'Web Attack',
    });
  }

  // Inject realistic CIC-IDS2017 data quality anomalies (duplicates, NaNs, Infinity)
  // so the preprocessing pipeline actively cleans and audits them before splitting.
  records.push({ ...records[0] }); // duplicate 1
  records.push({ ...records[12] }); // duplicate 2
  records.push({ ...records[650] }); // duplicate 3
  records.push({ ...records[760] }); // duplicate 4
  records[5] = { ...records[5], flowBytesPerSec: Number.POSITIVE_INFINITY };
  records[19] = { ...records[19], flowPacketsPerSec: Number.POSITIVE_INFINITY };
  records[660] = { ...records[660], flowBytesPerSec: Number.NaN };
  records[770] = { ...records[770], flowIatMean: Number.NaN };

  return records;
}
