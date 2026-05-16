import { Router } from 'express';
import { validateEvent } from '../middleware/validate.js';
import { addEvent, getAll, getBySession, getStats } from '../store/memory.js';
import { exportModelAsXML } from '../../../../core/src/xmlExporter.js';

const router = Router();

// POST /api/report — receive event from browser
router.post('/report', validateEvent, (req, res) => {
  addEvent(req.body);
  res.status(201).json({ ok: true });
});

// GET /api/events — return all events (used by React dashboard)
router.get('/events', (req, res) => {
  const { session, limit = 100 } = req.query;
  const events = session ? getBySession(session) : getAll();
  res.json(events.slice(-parseInt(limit)));
});

// GET /api/stats — aggregate statistics
router.get('/stats', (req, res) => res.json(getStats()));

// GET /api/export — download all events as JSON (for paper evaluation)
router.get('/export', (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="adaptxss_events.json"');
  res.json(getAll());
});

router.get('/model-xml', (req, res) => {
  const events = getAll();
  const classifierState = {
    classCounts: { malicious: 1, benign: 1 },
    featureCounts: { malicious: new Array(8).fill(1), benign: new Array(8).fill(1) },
    totalSamples: 2,
    version: 1
  };
  for (const e of events) {
    classifierState.totalSamples++;
    classifierState.classCounts[e.label]++;
    for (let i = 0; i < 8; i++) {
      if (e.features[i] > 0.5) classifierState.featureCounts[e.label][i]++;
    }
  }
  const xml = exportModelAsXML(classifierState);
  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', 'attachment; filename="model_rules.xml"');
  res.send(xml);
});

export default router;
