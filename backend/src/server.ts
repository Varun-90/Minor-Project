/**
 * NetShield AI Full-Stack Server (Express + Vite Dev Middleware / Static Prod)
 * Exposes all /api/v1/* endpoints backed by the genuine Random Forest ML pipeline.
 */

import 'dotenv/config';
import express from 'express';
import path from 'path';
import multer from 'multer';
import { z } from 'zod';
import { createServer as createViteServer } from 'vite';
import { mlPipeline } from '../../ml/src/pipeline.ts';
import { store } from './store.ts';
import {
  AuthenticatedRequest,
  authenticateLocalUser,
  bootstrapLocalAdmin,
  createLocalUser,
  isEnvPasswordConfigured,
  isLocalBootstrapRequired,
  listLocalUsers,
  requireAuth,
  requireRole,
  signLocalToken,
  updateLocalUserRole,
} from './auth.ts';

const PORT = 3000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // 5 MB strict limit
    files: 1,
  },
  fileFilter: (_req, file, cb) => {
    const lower = file.originalname.toLowerCase();
    if (!lower.endsWith('.csv') && !file.mimetype.includes('csv') && file.mimetype !== 'text/plain') {
      cb(new Error('Only CSV files (.csv) are permitted for network-flow import.'));
      return;
    }
    cb(null, true);
  },
});

const loginSchema = z.object({
  username: z.string().min(2).max(64),
  password: z.string().min(1).max(128),
});

const bootstrapSchema = z.object({
  username: z.string().min(3).max(40),
  password: z.string().min(8).max(128),
});

const singleFlowSchema = z.object({
  eventTime: z.string().max(64).optional(),
  srcIp: z.string().min(3).max(64).default('192.168.10.15'),
  dstIp: z.string().min(3).max(64).default('192.168.10.50'),
  srcPort: z.coerce.number().int().min(0).max(65535).default(51420),
  dstPort: z.coerce.number().int().min(0).max(65535).default(80),
  protocol: z.enum(['TCP', 'UDP', 'ICMP', 'OTHER']).default('TCP'),
  flowDuration: z.coerce.number().min(0).default(120000),
  totalFwdPackets: z.coerce.number().min(0).default(10),
  totalBwdPackets: z.coerce.number().min(0).default(8),
  totalLenFwdPackets: z.coerce.number().min(0).default(1200),
  totalLenBwdPackets: z.coerce.number().min(0).default(4800),
  fwdPacketLenMean: z.coerce.number().min(0).optional(),
  bwdPacketLenMean: z.coerce.number().min(0).optional(),
  flowBytesPerSec: z.coerce.number().min(0).optional(),
  flowPacketsPerSec: z.coerce.number().min(0).optional(),
  flowIatMean: z.coerce.number().min(0).default(8000),
  synFlagCount: z.coerce.number().min(0).default(1),
  ackFlagCount: z.coerce.number().min(0).default(10),
  finFlagCount: z.coerce.number().min(0).default(1),
  rstFlagCount: z.coerce.number().min(0).default(0),
  pshFlagCount: z.coerce.number().min(0).default(4),
});

const alertPatchSchema = z.object({
  status: z.enum(['Open', 'Investigating', 'Resolved']),
});

const settingsPatchSchema = z.object({
  pollingIntervalSec: z.number().min(0).max(300).optional(),
  criticalThreshold: z.number().min(0.5).max(0.99).optional(),
  highThreshold: z.number().min(0.4).max(0.95).optional(),
  mediumThreshold: z.number().min(0.3).max(0.9).optional(),
  lowThreshold: z.number().min(0.2).max(0.85).optional(),
  zeekIntegrationEnabled: z.boolean().optional(),
});

const retrainSchema = z.object({
  nEstimators: z.number().int().min(5).max(100).default(30),
  maxDepth: z.number().int().min(3).max(20).default(9),
});

const createUserSchema = z.object({
  username: z.string().min(3).max(40),
  password: z.string().min(8).max(128),
  role: z.enum(['admin', 'analyst', 'viewer']),
});

const updateUserRoleSchema = z.object({
  role: z.enum(['admin', 'analyst', 'viewer']),
});

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '2mb' }));

  // --- Public Health Endpoint ---
  app.get('/api/v1/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'NetShield AI Threat Detection API',
      mode: store.settings.detectionMode,
      activeModelVersion: mlPipeline.activeMetrics.version,
      timestamp: new Date().toISOString(),
    });
  });

  // --- Authentication Endpoints ---
  app.get('/api/v1/auth/status', (_req, res) => {
    res.json({
      localBootstrapRequired: isLocalBootstrapRequired(),
      envPasswordConfigured: isEnvPasswordConfigured(),
    });
  });

  app.post('/api/v1/auth/bootstrap', (req, res) => {
    const parsed = bootstrapSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid bootstrap payload.' });
    }
    try {
      const record = bootstrapLocalAdmin(parsed.data.username, parsed.data.password);
      const user = {
        uid: record.id,
        username: record.username,
        email: record.email,
        role: record.role,
        authProvider: 'local' as const,
      };
      const token = signLocalToken(user);
      return res.status(201).json({ access_token: token, token_type: 'bearer', user });
    } catch (err: any) {
      return res.status(409).json({ error: err.message || 'Bootstrap already completed.' });
    }
  });

  app.post('/api/v1/auth/login', (req, res) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }
    const result = authenticateLocalUser(parsed.data.username, parsed.data.password);
    if (!result) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    return res.json({
      access_token: result.token,
      token_type: 'bearer',
      user: result.user,
    });
  });

  // --- Dashboard Summary ---
  app.get('/api/v1/dashboard/summary', requireAuth, (_req, res) => {
    res.json(store.getDashboardSummary());
  });

  // --- Sample CIC-IDS2017 CSV Download ---
  app.get('/api/v1/events/sample-csv', requireAuth, (_req, res) => {
    const csv = mlPipeline.generateSampleCsv();
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="cic_ids2017_sample_flows.csv"');
    res.send(csv);
  });

  // --- Network Events List (Paginated & Filtered) ---
  app.get('/api/v1/events', requireAuth, (req, res) => {
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const search = String(req.query.search || '').trim().toLowerCase();
    const prediction = String(req.query.prediction || '').trim();
    const protocol = String(req.query.protocol || '').trim();
    const severity = String(req.query.severity || '').trim();

    let filtered = store.events;
    if (search) {
      filtered = filtered.filter(
        (e) =>
          e.srcIp.toLowerCase().includes(search) ||
          e.dstIp.toLowerCase().includes(search) ||
          e.attackType.toLowerCase().includes(search) ||
          String(e.dstPort).includes(search) ||
          e.protocol.toLowerCase().includes(search)
      );
    }
    if (prediction && prediction !== 'All') {
      filtered = filtered.filter((e) => e.prediction === prediction);
    }
    if (protocol && protocol !== 'All') {
      filtered = filtered.filter((e) => e.protocol === protocol);
    }
    if (severity && severity !== 'All') {
      filtered = filtered.filter((e) => e.severity === severity);
    }

    const total = filtered.length;
    const start = (page - 1) * limit;
    const items = filtered.slice(start, start + limit);

    res.json({
      items,
      total,
      page,
      limit,
      totalPages: Math.max(1, Math.ceil(total / limit)),
    });
  });

  // --- Single Network Event Details ---
  app.get('/api/v1/events/:id', requireAuth, (req, res) => {
    const evt = store.events.find((e) => e.id === req.params.id);
    if (!evt) {
      return res.status(404).json({ error: 'Network event not found.' });
    }
    const linkedAlert = store.alerts.find((a) => a.eventId === evt.id) || null;
    return res.json({ event: evt, alert: linkedAlert });
  });

  // --- Single Flow Prediction ---
  app.post('/api/v1/predictions', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
    const parsed = singleFlowSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Validation failed for network-flow input.',
        details: parsed.error.issues,
      });
    }
    try {
      const pred = mlPipeline.predictFlow(parsed.data, store.getAlertPolicy());
      const { event, alert } = store.recordPrediction(pred, 'Manual Single-Flow Analysis');
      return res.status(201).json({ event, alert });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Prediction failed.' });
    }
  });

  // --- Batch CSV Import & Analysis ---
  app.post(
    '/api/v1/events/import',
    requireAuth,
    requireRole('admin', 'analyst'),
    (req, res) => {
      upload.single('file')(req, res, (uploadErr: any) => {
        if (uploadErr) {
          return res.status(400).json({ error: uploadErr.message || 'CSV upload validation failed.' });
        }
        if (!req.file) {
          return res.status(400).json({ error: 'No CSV file provided. Use multipart field "file".' });
        }

        try {
          const csvText = req.file.buffer.toString('utf-8');
          const { predictions, cleaningReport } = mlPipeline.analyzeCsv(csvText, store.getAlertPolicy());

          if (predictions.length > 500) {
            return res.status(400).json({
              error: 'Batch size exceeds 500 flow records per upload. Split the CSV into smaller batches.',
            });
          }

          const batchName = req.file.originalname.slice(0, 120);
          const createdEvents = [];
          const createdAlerts = [];

          for (const pred of predictions) {
            const { event, alert } = store.recordPrediction(pred, batchName);
            createdEvents.push(event);
            if (alert) createdAlerts.push(alert);
          }

          return res.status(201).json({
            batchName,
            cleaningReport,
            importedCount: createdEvents.length,
            suspiciousCount: createdAlerts.length,
            normalCount: createdEvents.length - createdAlerts.length,
            events: createdEvents,
            alerts: createdAlerts,
          });
        } catch (err: any) {
          return res.status(400).json({ error: err.message || 'Failed to parse and classify CSV file.' });
        }
      });
    }
  );

  // --- Alerts List & Update ---
  app.get('/api/v1/alerts', requireAuth, (req, res) => {
    const status = String(req.query.status || '').trim();
    const severity = String(req.query.severity || '').trim();
    const search = String(req.query.search || '').trim().toLowerCase();

    let filtered = store.alerts;
    if (status && status !== 'All') {
      filtered = filtered.filter((a) => a.status === status);
    }
    if (severity && severity !== 'All') {
      filtered = filtered.filter((a) => a.severity === severity);
    }
    if (search) {
      filtered = filtered.filter(
        (a) =>
          a.description.toLowerCase().includes(search) ||
          a.srcIp.toLowerCase().includes(search) ||
          a.dstIp.toLowerCase().includes(search) ||
          a.attackType.toLowerCase().includes(search)
      );
    }

    res.json({
      items: filtered,
      total: filtered.length,
    });
  });

  app.patch('/api/v1/alerts/:id', requireAuth, requireRole('admin', 'analyst'), (req: AuthenticatedRequest, res) => {
    const parsed = alertPatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid status. Must be Open, Investigating, or Resolved.' });
    }
    const alert = store.alerts.find((a) => a.id === req.params.id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found.' });
    }
    if (alert.status === 'Resolved' && req.user?.role !== 'admin') {
      return res.status(403).json({ error: 'Resolved alerts can only be reopened by an administrator.' });
    }
    alert.status = parsed.data.status;
    alert.updatedAt = new Date().toISOString();
    alert.resolvedAt = parsed.data.status === 'Resolved' ? alert.updatedAt : '';
    return res.json({ alert });
  });

  // --- Model Metrics & Retraining ---
  app.get('/api/v1/models/metrics', requireAuth, (_req, res) => {
    res.json({
      activeModel: mlPipeline.activeMetrics,
      history: mlPipeline.evaluationHistory,
    });
  });

  app.post('/api/v1/models/retrain', requireAuth, requireRole('admin'), (req, res) => {
    const parsed = retrainSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid hyperparameter configuration.' });
    }
    try {
      const metrics = mlPipeline.trainNewVersion({
        nEstimators: parsed.data.nEstimators,
        maxDepth: parsed.data.maxDepth,
      });
      return res.status(201).json({
        activeModel: metrics,
        history: mlPipeline.evaluationHistory,
      });
    } catch (err: any) {
      return res.status(500).json({ error: err.message || 'Model retraining failed.' });
    }
  });

  // --- Settings & Policy Configuration ---
  app.get('/api/v1/settings', requireAuth, (_req, res) => {
    res.json({ settings: store.settings });
  });

  app.patch('/api/v1/settings', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
    const parsed = settingsPatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid configuration parameters.' });
    }
    store.settings = {
      ...store.settings,
      ...parsed.data,
      detectionMode: 'detection_only',
    };
    return res.json({ settings: store.settings });
  });

  // --- User Management (Admin Only) ---
  app.get('/api/v1/users', requireAuth, requireRole('admin'), (_req, res) => {
    res.json({ users: listLocalUsers() });
  });

  app.post('/api/v1/users', requireAuth, requireRole('admin'), (req, res) => {
    const parsed = createUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.issues[0]?.message || 'Invalid user data.' });
    }
    try {
      const user = createLocalUser(parsed.data.username, parsed.data.password, parsed.data.role);
      return res.status(201).json({ user });
    } catch (err: any) {
      return res.status(409).json({ error: err.message });
    }
  });

  app.patch('/api/v1/users/:id', requireAuth, requireRole('admin'), (req, res) => {
    const parsed = updateUserRoleSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid role.' });
    }
    const updated = updateLocalUserRole(req.params.id, parsed.data.role);
    if (!updated) {
      return res.status(404).json({ error: 'User not found.' });
    }
    return res.json({ user: updated });
  });

  // --- Optional Decoupled Zeek conn.log Parser Preview ---
  app.post('/api/v1/zeek/parse', requireAuth, requireRole('admin', 'analyst'), (req, res) => {
    const rawLine = typeof req.body?.zeekJson === 'string' ? req.body.zeekJson.trim() : '';
    if (!rawLine) {
      return res.status(400).json({ error: 'Provide a valid Zeek JSON conn.log record.' });
    }
    try {
      const zObj = JSON.parse(rawLine) as Record<string, unknown>;
      const durationUs = Math.max(0, Number(zObj.duration ?? 0.25) * 1_000_000);
      const origPkts = Number(zObj.orig_pkts ?? 1);
      const respPkts = Number(zObj.resp_pkts ?? 0);
      const origBytes = Number(zObj.orig_bytes ?? 0);
      const respBytes = Number(zObj.resp_bytes ?? 0);
      const proto = String(zObj.proto ?? 'tcp').toUpperCase();

      const pred = mlPipeline.predictFlow(
        {
          eventTime: zObj.ts ? new Date(Number(zObj.ts) * 1000).toISOString() : new Date().toISOString(),
          srcIp: String(zObj['id.orig_h'] ?? '192.168.10.15'),
          dstIp: String(zObj['id.resp_h'] ?? '192.168.10.50'),
          srcPort: Number(zObj['id.orig_p'] ?? 51000),
          dstPort: Number(zObj['id.resp_p'] ?? 80),
          protocol: proto === 'UDP' ? 'UDP' : proto === 'ICMP' ? 'ICMP' : 'TCP',
          flowDuration: durationUs,
          totalFwdPackets: origPkts,
          totalBwdPackets: respPkts,
          totalLenFwdPackets: origBytes,
          totalLenBwdPackets: respBytes,
          synFlagCount: String(zObj.conn_state ?? '').includes('S') ? 1 : 0,
          rstFlagCount: String(zObj.conn_state ?? '').includes('R') ? 1 : 0,
        },
        store.getAlertPolicy()
      );
      const { event, alert } = store.recordPrediction(pred, 'Zeek conn.log Adapter');
      return res.status(201).json({ event, alert });
    } catch {
      return res.status(400).json({ error: 'Invalid Zeek JSON format.' });
    }
  });

  // --- Frontend Serving (Vite Dev Middleware or Static Production Build) ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`NetShield AI server running on http://0.0.0.0:${PORT}`);
    console.log(
      `Active ML Model: ${mlPipeline.activeMetrics.algorithm} ${mlPipeline.activeMetrics.version} | Accuracy: ${(
        mlPipeline.activeMetrics.accuracy * 100
      ).toFixed(2)}% (held-out n=${mlPipeline.activeMetrics.testSamples})`
    );
  });
}

startServer().catch((err) => {
  console.error('Fatal server startup error:', err);
  process.exit(1);
});
