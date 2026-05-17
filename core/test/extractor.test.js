// core/test/extractor.test.js

import { JSDOM }          from 'jsdom';
import { extractFeatures } from '../src/extractor.js';

let dom;
beforeEach(() => {
  dom = new JSDOM('<!DOCTYPE html><html><body><div id="root"></div></body></html>');
});

function makeNode(html) {
  const wrapper = dom.window.document.createElement('div');
  wrapper.innerHTML = html;
  return wrapper.firstChild || wrapper;
}

function makeMutation(html) {
  const root = dom.window.document.getElementById('root');
  const node = makeNode(html);
  return { addedNodes: [node], target: root };
}

describe('extractFeatures', () => {

  test('Returns Float32Array of length 8', () => {
    const f = extractFeatures(makeMutation('<div>Hello</div>'));
    expect(f).toBeInstanceOf(Float32Array);
    expect(f.length).toBe(8);
  });

  test('All values in [0, 1]', () => {
    const f = extractFeatures(makeMutation('<img src="x" onerror="alert(1)">'));
    for (const v of f) {
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(1);
    }
  });

  test('Clean div — risk features are zero', () => {
    const f = extractFeatures(makeMutation('<div>Hello World</div>'));
    expect(f[0]).toBe(0);   // tag_risk: div is not risky
    expect(f[1]).toBe(0);   // attr_delta: no dangerous attrs
    expect(f[2]).toBe(0);   // script_injection
    expect(f[3]).toBe(0);   // inline_handler
    expect(f[4]).toBe(0);   // url_anomaly
    expect(f[5]).toBe(0);   // data_uri
  });

  test('Script tag injection — f0=1, f2=1', () => {
    const f = extractFeatures(makeMutation('<script>alert(1)</script>'));
    expect(f[0]).toBe(1.0);
    expect(f[2]).toBe(1.0);
  });

  test('img onerror — f0=0.5 (medium), f3=1 (inline handler)', () => {
    const f = extractFeatures(makeMutation('<img onerror="alert(1)" src="x">'));
    expect(f[0]).toBe(0.5);
    expect(f[3]).toBe(1.0);
  });

  test('SVG with onload — f0=1 (high risk tag), f3=1', () => {
    const f = extractFeatures(makeMutation('<svg onload="alert(1)"></svg>'));
    expect(f[0]).toBe(1.0);
    expect(f[3]).toBe(1.0);
  });

  test('javascript: href — f4=1.0 (url anomaly)', () => {
    const f = extractFeatures(makeMutation('<a href="javascript:alert(1)">click</a>'));
    expect(f[4]).toBe(1.0);
  });

  test('vbscript: src — f4=1.0', () => {
    const f = extractFeatures(makeMutation('<img src="vbscript:msgbox(1)">'));
    expect(f[4]).toBe(1.0);
  });

  test('data: URI in src — f5=1', () => {
    const f = extractFeatures(makeMutation('<img src="data:image/png;base64,abc">'));
    expect(f[5]).toBe(1.0);
  });

  test('data: URI in href — f5=1', () => {
    const f = extractFeatures(makeMutation('<a href="data:text/html,<h1>XSS</h1>">x</a>'));
    expect(f[5]).toBe(1.0);
  });

  test('High-entropy obfuscated payload — f7 > 0.3', () => {
    const f = extractFeatures(makeMutation('<div>%3Cscript%3Ealert%281%29%3C%2Fscript%3E</div>'));
    expect(f[7]).toBeGreaterThan(0.3);
  });

  test('Normal paragraph — low entropy f7', () => {
    const f = extractFeatures(makeMutation('<p>Hello World this is a normal sentence</p>'));
    const fHigh = extractFeatures(makeMutation('<div>%3Cscript%3Ealert%281%29%3C%2Fscript%3E</div>'));
    expect(f[7]).toBeLessThan(fHigh[7]);  // normal text has lower entropy than obfuscated
  });

  test('Multiple dangerous attributes — f1 accumulates', () => {
    const f = extractFeatures(makeMutation('<a href="/x" data-v="1" poster="img.jpg">click</a>'));
    // href (0.25) + poster (0.25) = 0.50  ('data-v' is data-*, not the 'data' attr)
    expect(f[1]).toBeCloseTo(0.50, 1);
  });

  test('Handles null/undefined addedNodes gracefully', () => {
    const root = dom.window.document.getElementById('root');
    const f = extractFeatures({ addedNodes: [], target: root });
    expect(f).toBeInstanceOf(Float32Array);
    expect(f.length).toBe(8);
  });
});
