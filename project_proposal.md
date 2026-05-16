# Project Proposal: AdaptXSS — Adaptive DOM-Based XSS Detection via Incremental Pattern Learning

**Course:** CS365TDC — Web Frameworks (Sem VI, CS III Year 2022)
**Category:** Professional Core Elective-III | Theory

---

## 1. Problem Statement

Cross-Site Scripting (XSS) remains one of the most prevalent web vulnerabilities (OWASP Top-10, every year since 2003). Existing detection methods fall into two camps:

- **Static scanners** (e.g., OWASP ZAP, Burp Suite) — rule-based, miss obfuscated/novel payloads, high false-positive rate.
- **Deep learning models** (e.g., LSTM-based, BERT-fine-tuned) — heavyweight, require large labelled corpora, not deployable in-browser.

**The gap:** No lightweight, *adaptive*, browser-native system exists that learns XSS patterns incrementally from live DOM mutations without a server round-trip.

---

## 2. The Idea — AdaptXSS

**A client-side JavaScript library** that:

1. Hooks into the browser's `MutationObserver` API to watch real-time DOM changes.
2. Extracts a small feature vector from each mutation event (tag type, attribute delta, script injection signal, inline handler appearance, src/href anomaly score).
3. Runs an **incremental Naive Bayes classifier** (updated online, ~4 KB model weight file) to score each mutation as benign or malicious.
4. Optionally reports suspicious events to a Node.js/Express backend via Ajax for aggregate analysis.
5. Can be toggled via a lightweight dashboard (React frontend) showing live threat scores per page session.

**Key constraint:** The entire client-side engine must fit under 10 KB (minified), making it deployable in any web app without performance regression.

---

## 3. Why This Is Novel

| Dimension | Existing Work | AdaptXSS |
|---|---|---|
| Detection scope | Static payload scan | Live DOM mutation stream |
| Learning | Offline / batch | Online incremental (per session) |
| Deployment | Proxy / server plugin | Pure JS, browser-native |
| Model size | 10–500 MB (BERT etc.) | < 10 KB weights |
| Adaptability | Needs retraining | Updates with each new mutation |

No published work combines **MutationObserver-based feature extraction** with **online incremental learning** for XSS detection. The closest related works are:

- Heiderich et al. (2012) — DOM Clobbering attacks (describes threat, not mitigation)
- Bates et al. (2010) — Regular-expression XSS filters (static)
- Fang et al. (2019) — Deep learning XSS detection (offline, server-side)
- Chrome DevTools' Content Security Policy (CSP) — rule-based, not adaptive

---

## 4. Curriculum Alignment

The project directly exercises **every unit** of CS365TDC:

| Unit | Covered by |
|---|---|
| Unit I — JS basics | Feature extractor written in vanilla JS |
| Unit II — DOM & Events | MutationObserver, event interception |
| Unit III — PHP / XML | Backend log receiver in PHP; XML-based rule export |
| Unit IV — Angular, Node, React | React dashboard; Node.js aggregation server |
| Unit V — Ajax, Django | Ajax threat-report endpoint; optional Django admin panel |

---

## 5. Mathematical Framework and Comparability

### Feature Vector
For each DOM mutation event *e*, extract:

```
f(e) = [tag_risk, attr_delta, script_flag, handler_flag, url_anomaly_score]
```

Where `url_anomaly_score` = TF-IDF cosine similarity of the injected href/src against a known-benign URL corpus.

### Online Naive Bayes Classifier

Posterior update at each mutation:

```
P(malicious | f) ∝ P(malicious) · ∏ P(fᵢ | malicious)
```

Priors are updated incrementally:

```
P(fᵢ | c) = (count(fᵢ, c) + 1) / (count(c) + |V|)   [Laplace smoothing]
```

This allows exact comparison with baseline classifiers using standard metrics:

- **Precision**, **Recall**, **F1-score** on labelled XSS payload datasets (e.g., XSS-Payload-List by payloadbox on GitHub — 20,000+ entries)
- **Detection latency** (ms from injection to alert) vs server-side scanners
- **False Positive Rate** vs OWASP ZAP and Burp Suite
- **Model drift** — how F1 changes over N sessions without retraining vs with online update

### Baseline Comparison Table (expected, to be filled experimentally)

| System | Precision | Recall | F1 | Latency | Model Size |
|---|---|---|---|---|---|
| OWASP ZAP (static) | ~0.71 | ~0.68 | ~0.69 | 800ms+ | N/A |
| BERT-XSS (Fang 2019) | ~0.94 | ~0.91 | ~0.92 | 200ms | ~400 MB |
| **AdaptXSS (ours)** | TBD | TBD | TBD | <20ms | <10 KB |

The hypothesis: AdaptXSS achieves F1 ≥ 0.85 at <20ms latency with <10 KB model, a Pareto-superior point on the latency-accuracy tradeoff that no existing system occupies.

---

## 6. Deliverables

| # | Deliverable | Description |
|---|---|---|
| 1 | `adaptxss.js` | Core JS library (MutationObserver + online NB classifier) |
| 2 | React Dashboard | Live threat score visualizer per session |
| 3 | Node.js Backend | Aggregation server + REST API for threat logs |
| 4 | PHP Receiver | Lightweight fallback log endpoint |
| 5 | Evaluation Notebook | Python/Jupyter — F1, Precision, Recall, latency benchmarks |
| 6 | Research Paper Draft | IEEE/ACM format — Introduction, Related Work, Methodology, Results, Conclusion |

---

## 7. Research Paper Angle

**Title (draft):** *"AdaptXSS: Lightweight Online Learning for Real-Time DOM-Based Cross-Site Scripting Detection in Browser Environments"*

**Target venues:**
- IEEE International Conference on Web Services (ICWS)
- ACM Web Conference (WWW) — Security & Privacy track
- Computers & Security (Elsevier journal)

**Core claim:** A DOM-native, incrementally-learning XSS detector achieves competitive accuracy with orders-of-magnitude lower latency and model size than deep learning alternatives, enabling deployment in resource-constrained environments (IoT dashboards, mobile PWAs, embedded kiosks).

---

## 8. Implementation Plan (8 Weeks)

| Week | Milestone |
|---|---|
| 1–2 | Feature extractor + MutationObserver hook; unit tests on XSS payload dataset |
| 3 | Online Naive Bayes classifier; integration with extractor |
| 4 | Node.js aggregation backend + Ajax reporting |
| 5 | React dashboard (live threat visualization) |
| 6 | PHP fallback receiver; XML rule export module |
| 7 | Benchmark evaluation (vs ZAP, vs Fang 2019 baseline) |
| 8 | Paper draft + final demo |

---

## 9. Why This Satisfies Every Stated Condition

| Condition | How AdaptXSS meets it |
|---|---|
| Real problem, high implementation value | XSS is #1–3 web vulnerability every year; deployable as npm package |
| Highly novel | MutationObserver + online NB = no prior published combination |
| Clear problem and solution | Detect XSS at DOM mutation time, in-browser, adaptively |
| Research project, continuable | Future work: federated learning across sessions, adversarial robustness |
| Publishable | IEEE/ACM security + web track; novel system + benchmark = publishable unit |
| Mathematically comparable | Precision/Recall/F1/Latency/Model-size table vs named baselines |
| Not overkill, not too simple | Single JS library + React dashboard + Node backend = appropriately scoped |

---

*Generated via recursive multi-agent ideation (Proposer → Critic → Domain Judge → Meta-Judge) over web frameworks curriculum.*
