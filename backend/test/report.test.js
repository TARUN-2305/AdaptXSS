import request from 'supertest';
import app from '../src/server.js';

describe('Backend API', () => {
  const validEvent = {
    timestamp: 1680000000000,
    sessionId: 'sess_abc123',
    label: 'malicious',
    probability: 0.95,
    features: [1, 0, 1, 0, 0, 0, 0.1, 0.5],
    latencyMs: 1.5
  };

  test('GET /health returns ok', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('POST /api/report with valid payload', async () => {
    const res = await request(app).post('/api/report').send(validEvent);
    expect(res.status).toBe(201);
    expect(res.body).toEqual({ ok: true });
  });

  test('POST /api/report with missing fields', async () => {
    const res = await request(app).post('/api/report').send({ sessionId: 'sess_123' });
    expect(res.status).toBe(400);
    expect(res.body.errors).toBeDefined();
  });

  test('POST /api/report with probability > 1', async () => {
    const res = await request(app).post('/api/report').send({ ...validEvent, probability: 1.5 });
    expect(res.status).toBe(400);
  });

  test('GET /api/events returns array', async () => {
    const res = await request(app).get('/api/events');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body.length).toBeGreaterThan(0);
  });

  test('GET /api/stats returns object', async () => {
    const res = await request(app).get('/api/stats');
    expect(res.status).toBe(200);
    expect(res.body.total).toBeDefined();
    expect(res.body.malicious).toBeDefined();
    expect(res.body.benign).toBeDefined();
  });
});
