# NetShield AI — Network Threat Detection & Intrusion Monitoring System

AI-powered Network Intrusion Detection System (detection-only mode) using a Random Forest classifier trained on CIC-IDS2017 network-flow features.

## Monorepo Structure

```text
netshield-ai/
├── frontend/                   # React + Vite + Tailwind CSS monochrome dashboard
│   └── src/
│       ├── components/         # Layout, ErrorBoundary
│       ├── context/            # AuthContext (Firebase SSO + local API session)
│       ├── lib/                # Firebase client & Firestore persistence helpers
│       ├── pages/              # Login, Dashboard, Monitoring, Event Details, Analysis, Model, Alerts, Settings
│       ├── services/           # Axios /api/v1/* client
│       ├── App.tsx
│       ├── main.tsx
│       └── index.css
├── backend/                    # API server & authentication
│   ├── src/                    # Express /api/v1/* server, RBAC auth, event/alert store
│   └── python_fastapi/         # FastAPI + Pydantic + Pytest/HTTPX reference backend
├── ml/                         # Machine Learning pipeline & versioned artifacts
│   ├── src/                    # TypeScript Random Forest classifier, CIC-IDS2017 schema & evaluator
│   ├── python/                 # Scikit-learn + Joblib CIC-IDS2017 training script
│   └── artifacts/              # Serialized versioned model artifacts
├── database/                   # Database schemas & rules test specs
│   ├── mysql/schema.sql        # MySQL netshield_ai DDL (users, network_events, alerts, model_registry)
│   └── firestore/              # Firestore security rules Dirty Dozen test spec
├── docs/                       # Security specification & architecture documentation
├── firestore.rules             # Deployed Firestore security rules
├── firebase-blueprint.json     # Firestore data model blueprint
├── server.ts                   # Root server entrypoint delegating to backend/src/server.ts
├── index.html                  # Vite HTML entrypoint pointing to /frontend/src/main.tsx
└── package.json
```

## Running Locally

```bash
npm install
npm run dev
```

The application serves both the React frontend and `/api/v1/*` backend endpoints on `http://localhost:3000`.

### Python ML Training (Optional Standalone CIC-IDS2017 Training)

```bash
pip install -r ml/python/requirements.txt
python ml/python/train_cicids2017.py --data-dir /path/to/cicids2017_csvs --out-dir ml/artifacts --version v1.0.0
```

## Pushing to GitHub

Use the **Save to GitHub** button in AI Studio, or push from your local clone:

```bash
git remote add origin https://github.com/<your-username>/<your-repo>.git
git branch -M main
git push -u origin main
```
