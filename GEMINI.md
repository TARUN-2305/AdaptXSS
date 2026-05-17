# AdaptXSS: Adaptive DOM-Based XSS Detection

AdaptXSS is a lightweight, browser-native XSS detection system that uses an online incremental Bernoulli Naive Bayes classifier to monitor DOM mutations in real-time. It aims to bridge the gap between static scanners and heavy deep learning models by being adaptive, performant (< 10 KB bundle, < 5 ms latency), and browser-native.

## 🏗 Project Structure

The repository is organized into several key components:

-   **`core/`**: The heart of the project. A vanilla JavaScript library that implements:
    -   `MutationObserver` hooks (`observer.js`)
    -   8-dimensional feature extraction (`extractor.js`)
    -   Online Bernoulli Naive Bayes classifier (`classifier.js`)
    -   Reporting logic with exponential backoff (`reporter.js`)
-   **`backend/`**: A Node.js Express server that aggregates reported XSS events, provides statistics, and exports model weights as XML.
-   **`dashboard/`**: A React + Vite frontend for real-time monitoring of threat feeds and session statistics.
-   **`adaptxss_admin/`**: A Django 6 admin panel for persistent storage and management of XSS events using SQLite.
-   **`php-receiver/`**: A simple PHP fallback receiver for environments where Node.js is not available.
-   **`evaluation/`**: Benchmarking tools (Jupyter notebooks and Python scripts) to compare AdaptXSS against baselines like OWASP ZAP.
-   **`paper/`**: LaTeX source for the research paper documenting the system design and evaluation.

## 🚀 Building and Running

### Prerequisites
- Node.js ≥ 18
- Python ≥ 3.10
- npm ≥ 9

### Core Library
```bash
cd core
npm install
node scripts/pretrain.js  # Seed model from dataset
npm run build            # Build minified bundle (dist/adaptxss.min.js)
npm test                 # Run Jest tests
npm run size             # Verify bundle size (< 10 KB)
```

### Aggregation Backend
```bash
cd backend
npm install
npm start               # Start server on http://localhost:4000
# Use 'npm run dev' for watch mode
```

### Monitoring Dashboard
```bash
cd dashboard
npm install
npm run dev             # Start Vite dev server on http://localhost:5173
```

### Django Admin Panel
```bash
cd adaptxss_admin
pip install django djangorestframework django-cors-headers
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver  # Start on http://localhost:8000
```

### Evaluation
```bash
cd evaluation
pip install scikit-learn pandas numpy matplotlib jupyter
jupyter notebook benchmark.ipynb
```

## 🛠 Development Conventions

### Technologies
- **Client-side**: Vanilla JS (ESM), `MutationObserver`, `localStorage`.
- **Backend**: Node.js, Express, `helmet`, `cors`, `express-validator`.
- **Frontend**: React 19, Vite, Recharts, Axios.
- **Admin**: Django 6, Django REST Framework.
- **Testing**: Jest (Core/Backend), Vitest/Testing Library (Dashboard).

### Key Rules & Practices
- **Bundle Size**: The core library MUST remain under 10 KB (minified). Always run `npm run size` after changes to `core/src/`.
- **Zero Dependencies**: The core library (in `dist/`) must have zero external runtime dependencies.
- **Incremental Learning**: The classifier in `core/` updates its weights live. Ensure any changes to `classifier.js` maintain the ability to serialize/deserialize state to `localStorage`.
- **Feature Consistency**: The 8-dimensional feature vector is shared across the library and backend. Ensure `extractor.js` and backend validation stay in sync.
- **Testing**: Every bug fix or new feature must be accompanied by tests in the respective `test/` directory.

## 📝 Key Files

-   `core/src/classifier.js`: Implementation of the Online Bernoulli NB.
-   `core/src/extractor.js`: Logic for mapping DOM mutations to the 8-feature vector.
-   `backend/src/server.js`: Main Express application and API endpoints.
-   `dashboard/src/App.jsx`: Main dashboard entry point.
-   `adaptxss_admin/monitor/models.py`: Django model for `XSSEvent`.
-   `evaluation/benchmark.ipynb`: Primary evaluation script.

## 📚 Documentation

-   `AdaptXSS_Action_Plan.md`: The original 9-phase implementation plan.
-   `DEMO_GUIDE.md`: Detailed instructions on how to use the interactive demo.
-   `project_proposal.md`: Original research proposal and justification.
-   `session_log.md`: Log of development sessions and context.
