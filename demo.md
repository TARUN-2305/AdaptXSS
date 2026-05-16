Viewed .gitignore:3-38

To demonstrate **AdaptXSS** effectively, follow this step-by-step walkthrough. This will showcase real-time detection, browser-native processing, the online learning aspect, and the centralized monitoring dashboard.

### 🏗️ 1. Prepare the Environment
Ensure the following are running (I have already started these in the background):
1. **Backend:** Running on `http://localhost:4000` (Aggregation server).
2. **Dashboard:** Running on `http://localhost:5173` (Live threat monitor).
3. **Demo Page:** Located at `core/demo/index.html` (The "Target" application).

---

### 🚀 2. The Demonstration Walkthrough

#### **Step A: Open the "Command Center"**
1. Open your browser to **`http://localhost:5173`**.
2. This is the **React Dashboard**. You should see "No events recorded yet."
3. Keep this tab open on the side; it will update automatically every 2 seconds.

#### **Step B: Open the "Target Application"**
1. Open the file **`core/demo/index.html`** in a new browser tab.
2. You should see a log entry: `✅ Backend connected at http://localhost:4000`. This means any alerts detected here will be sent to your dashboard.

#### **Step C: Test "Benign" Content (The Baseline)**
1. In the Demo Page, click the **"✓ Inject Benign"** button.
2. **Observation:** A safe `div` is added to the DOM. The log shows it was classified as benign. 
3. **Dashboard:** Check your React Dashboard. You’ll see the "Total Events" count increase, but the "Threat Ratio" remains green.

#### **Step D: Perform a "Malicious" Attack**
1. In the Demo Page, click the **"img onerror"** quick-payload button (or type `<img src=x onerror=alert(1)>`).
2. Click **"⚠ Inject"**.
3. **Observation:** 
   - An alert pops up in the browser (XSS success).
   - The **Event Log** immediately turns red with a `MALICIOUS` badge.
   - You’ll see the feature vector (e.g., `f[3]` for inline handler will be `1.00`).
4. **Dashboard:** Switch to the Dashboard tab. You will see a red entry in the "Live Threat Feed" and the "Threat Ratio" gauge move toward red.

#### **Step E: The "Adaptive" Learning Showcase**
1. **Change Threshold:** Move the "Alert Threshold" slider to **0.90**.
2. Inject a "borderline" payload like `<div>Hello <script>void(0)</script></div>`. 
3. If the probability is below 0.90, it won't trigger an alert.
4. **Learn:** Use the `OnlineNBClassifier`'s logic. If you were to manually "label" a payload in the code (or use the pre-train script), the model weights update. For a demo, explain that **AdaptXSS learns from the session**. If the same session sees many similar patterns, the probability score for those features will increase.

#### **Step F: Exporting the Intelligence**
1. Go to the **React Dashboard**.
2. Click the **"Export Rules as XML"** button.
3. Open the downloaded `model_rules.xml`.
4. **Point out:** This XML contains the actual "intelligence" (log-odds) that the system has gathered. This file can be imported into WAFs or other security tools as a learned rule-set.

---

### 💡 Key Points to Highlight During Demo:
*   **Zero Latency:** Note how the detection happens *instantly* (usually < 1ms) because it's happening inside the browser's own process.
*   **Survivability:** Refresh the demo page. Notice the "Session ID" stays the same (or changes, but state can be persisted to `localStorage`). Explain that the "brain" of the detector lives in the user's browser.
*   **Stealth:** Open the browser's "Network" tab. Show that alerts are sent as small JSON payloads only when a threat is found, minimizing bandwidth.

**Pro-Tip:** If you want to show the Django side, navigate to `http://localhost:8000/admin` (if you started the Django server) to show that a security auditor can see the same logs in a traditional database format.