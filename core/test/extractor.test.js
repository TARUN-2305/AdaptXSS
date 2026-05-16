import { JSDOM } from 'jsdom';
import { extractFeatures } from '../src/extractor.js';

describe('extractor', () => {
  let dom;
  beforeEach(() => {
    dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>');
  });

  function getMutation(html) {
    const root = dom.window.document.getElementById('root');
    const div = dom.window.document.createElement('div');
    div.innerHTML = html;
    const node = div.firstChild;
    return { addedNodes: [node], target: root };
  }

  test('Clean div', () => {
    const mut = getMutation('<div>Hello</div>');
    const f = extractFeatures(mut);
    // Depth is calculated based on parent nodes. The node in getMutation is not attached to root yet.
    // So depth will be 0. We expect f6=0.
    // 1 / 20 = 0.05 (in Float32 it is ~0.05000000074505806)
    expect(f[0]).toBe(0);
    expect(f[1]).toBe(0);
    expect(f[2]).toBe(0);
    expect(f[3]).toBe(0);
    expect(f[4]).toBe(0);
    expect(f[5]).toBe(0);
    expect(f[6]).toBeCloseTo(0.05);
  });

  test('Script tag injection', () => {
    const mut = getMutation('<script>alert(1)</script>');
    const f = extractFeatures(mut);
    expect(f[0]).toBe(1.0);
    expect(f[2]).toBe(1.0);
  });

  test('XSS via onerror', () => {
    const mut = getMutation('<img onerror="alert(1)">');
    const f = extractFeatures(mut);
    expect(f[0]).toBe(0.5);
    expect(f[3]).toBe(1.0);
  });

  test('javascript: href', () => {
    const mut = getMutation('<a href="javascript:alert(1)">');
    const f = extractFeatures(mut);
    expect(f[4]).toBe(1.0);
  });

  test('data: URI', () => {
    const mut = getMutation('<img src="data:image/png;base64,...">');
    const f = extractFeatures(mut);
    expect(f[5]).toBe(1.0);
  });

  test('High entropy payload', () => {
    const mut = getMutation('<div>%3Cscript%3E</div>');
    const f = extractFeatures(mut);
    expect(f[7]).toBeGreaterThan(0.1); 
  });
});
