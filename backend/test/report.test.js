import request from 'supertest';
import app from '../src/server.js';
import { _resetStore } from '../src/store/memory.js';

const validEvent = {
  timestamp: 1680000000000,
  sessionId: 'sess_abc123_1680000000',
  label: 'malicious',
  probability: 0.95,
  features: [1, 0, 1, 0, 0, 0, 0.1, 0.5],
  latencyMs: 1.5
};

beforeEach(() => _resetStore());

describe('Health', () => {
  test('GET /health returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });
});

describe('POST /api/report', () => {
  test('valid payload → 201', async () => {
    const res = await request(app).post('/api/report').send(validEvent);
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ ok: true });
  });

  test('missing fields → 400 with errors array', async () => {
    const res = await request(app).post('/api/report').send({ sessionId: 'sess_123_000' });
    expect(res.status).toBe(400);
    expect(Array.isArray(res.body.errors)).toBe(true);
    expect(res.body.errors.length).toBeGreaterThan(0);
  });

  test('probability > 1 → 400', async () => {
    const res = await request(app).post('/api/report').send({ ...validEvent, probability: 1.5 });
    expect(res.status).toBe(400);
  });

  test('invalid label → 400', async () => {
    const res = await request(app).post('/api/report').send({ ...validEvent, label: 'unknown' });
    expect(res.status).toBe(400);
  });

  test('features wrong length → 400', async () => {
    const res = await request(app).post('/api/report').send({ ...validEvent, features: [1, 0, 1] });
    expect(res.status).toBe(400);
  });
});

describe('GET /api/events', () => {
  test('returns array (empty initially)', async () => {
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  test('returns events after posting', async () => {
    await request(app).post('/api/report').send(validEvent);
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(200);
    expect(res.body.length).toBe(1);
    expect(res.body[0].label).toBe('malicious');
  });

  test('session filter works', async () => {
    await request(app).post('/api/report').send(validEvent);
    await request(app).post('/api/report').send({
      ...validEvent,
      sessionId: 'sess_other_1680000001',
      label: 'benign',
      probability: 0.1
    });
    const res = await request(app).get(`/api/events?session=${validEvent.sessionId}`);
    expect(res.status).toBe(200);
    expect(res.body.every(e => e.sessionId === validEvent.sessionId)).toBe(true);
  });
});

describe('GET /api/stats', () => {
  test('returns object with required keys', async () => {
    const res = await request(app).get('/api/stats');
    expect(res.status).toBe(200);
    expect(typeof res.body.total).toBe('number');
    expect(typeof res.body.malicious).toBe('number');
    expect(typeof res.body.benign).toBe('number');
    expect(typeof res.body.sessions).toBe('number');
    expect(typeof res.body.avgLatencyMs).toBe('number');
    expect(typeof res.body.p99LatencyMs).toBe('number');
  });

  test('counts are accurate after posting', async () => {
    await request(app).post('/api/report').send(validEvent);
    await request(app).post('/api/report').send({ ...validEvent, label: 'benign', probability: 0.1 });
    const res = await request(app).get('/api/stats');
    expect(res.body.total).toBe(2);
    expect(res.body.malicious).toBe(1);
    expect(res.body.benign).toBe(1);
  });
});

describe('GET /api/model-xml', () => {
  test('returns valid XML', async () => {
    await request(app).post('/api/report').send(validEvent);
    const res = await request(app).get('/api/model-xml');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/xml/);
    expect(res.text).toContain('<?xml');
    expect(res.text).toContain('<adaptxss_model');
  });
});
