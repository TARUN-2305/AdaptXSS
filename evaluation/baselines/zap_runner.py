"""
evaluation/baselines/zap_runner.py
Placeholder runner for OWASP ZAP baseline measurements.
Requires ZAP to be running locally (default port 8090) with API key configured.

Usage:
  python zap_runner.py payloads.txt results.json

Install: pip install python-owasp-zap-v2.4
"""

import sys, json, time

def run_zap_scan(payloads_file, output_file):
    results = []
    try:
        from zapv2 import ZAPv2
        zap = ZAPv2(apikey='', proxies={'http': 'http://localhost:8090', 'https': 'http://localhost:8090'})
        print(f"[ZAP] Connected: {zap.core.version}")
    except Exception as e:
        print(f"[ZAP] Not available: {e}. Generating mock results for structure.")
        with open(payloads_file) as f:
            payloads = [l.strip() for l in f if l.strip()]
        for payload in payloads[:100]:
            # Mock: simple heuristic
            is_xss = any(kw in payload.lower() for kw in ['<script', 'javascript:', 'onerror', 'onload', 'alert'])
            results.append({'payload': payload, 'detected': is_xss, 'latency_ms': 850.0, 'tool': 'ZAP_MOCK'})
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[ZAP] Mock results written to {output_file}")
        return

if __name__ == '__main__':
    payloads_file = sys.argv[1] if len(sys.argv) > 1 else '../datasets/xss_payloads.txt'
    output_file   = sys.argv[2] if len(sys.argv) > 2 else '../datasets/zap_results.json'
    run_zap_scan(payloads_file, output_file)
