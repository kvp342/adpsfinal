# Chat Log (Summary)

This file is a saved summary of the work and troubleshooting done in this session for the APDS project.

## What the project is
- Full-stack demo: Spring Boot backend + React (Vite) frontend dashboard.
- Goal: log requests/events, score them (NORMAL/SUSPICIOUS/BLOCKED), persist to DB, show live dashboard, and support ML training (live logs + dataset-based).

## Backend (what we covered)
- Entry point: Spring Boot app with CORS enabled for `/api/**`.
- Request capture: a servlet filter logs requests (excluding dashboard polling endpoints) and forwards them into detection logic.
- Detection core:
  - Rule-based scoring (rate checks + SQLi/XSS/traversal/probing + scanner UA).
  - Strike tracking + temporary IP blocks.
  - Persists `SecurityLog` + `IpBlock`.
- Dataset pipeline:
  - Upload CSV → stored under `backend/data/uploads` and metadata stored in DB.
  - Dataset training uses Weka classifiers and reports status to dashboard.

## Frontend (what we covered)
- Dashboard polls the backend for stats/logs/blocks/ML status.
- UI supports:
  - Simulated attacks (POST to `/api/log`)
  - Unblock (POST `/api/unblock`)
  - Train live-log ML (POST `/api/ml/train`)
  - Upload dataset (POST `/api/datasets/upload`)
  - Train dataset ML (POST `/api/ml/dataset/train`)

## Changes implemented in code
- Auto-train live-log ML in backend:
  - Added a scheduled auto-trainer service and enabled scheduling.
  - Trains automatically once enough logs exist and retrains when enough new logs arrive.
- Fixed Maven dependency for XGBoost:
  - Updated artifact from `xgboost4j` to `xgboost4j_2.12`.
- Added dataset evaluation endpoint:
  - Added `/api/ml/dataset/evaluate` to compute accuracy and provide sample predictions.
- Improved dataset ML evaluation:
  - Cross-validation now returns TP/TN/FP/FN from cross-validation results.
  - Added feature selection (InfoGain + Ranker) via `FilteredClassifier` to improve generalization.
- Fixed CICIDS2017 duplicate header names:
  - Dataset loader now makes duplicate attribute names unique.
- Restored `run_frontend.bat` into project root (it was missing).
- Updated `run_backend.bat` to use `-U` and `clean` to force rebuild and dependency refresh.
- Added `.gitignore` and `README.md` to help with GitHub upload/sharing.
- UI improvement: dataset training button now indicates you must select a dataset before training.
- UI theme improvement: dashboard dark theme + animated glow + modern styling.

## Key troubleshooting outcomes
- If `http://localhost:8080` cannot be reached:
  - Backend is not running or failed to start. Check the backend console for Maven/compile errors.
- If dataset upload doesn’t work:
  - Backend must be running (port 8080 reachable) because upload hits `/api/datasets/upload`.
- If `npm` fails in PowerShell:
  - PowerShell script execution policies can block `npm.ps1`. Use `npm.cmd` or run via the provided `.bat` scripts.
- Dataset training showing `Holdout Acc: 0%` while status is `Training...`:
  - Accuracy updates after training completes; 0% during training is normal.

## How to run (Windows)
- Run both: `run_all.bat`
- Backend only: `run_backend.bat`
- Frontend only: `run_frontend.bat`
- URLs:
  - Dashboard: `http://localhost:5173`
  - Backend: `http://localhost:8080/hello`

## Dataset evaluation (API)
- List datasets:
  - `GET http://localhost:8080/api/datasets`
- Evaluate dataset model:
  - `POST http://localhost:8080/api/ml/dataset/evaluate?datasetId=...&model=RANDOM_FOREST&maxRows=50000&samples=10&folds=5`
  - If you want to open evaluation from a browser link, ensure backend supports `GET /api/ml/dataset/evaluate` (restart backend after updates).

## Dataset notes (current run)
- Example CICIDS2017 file uploaded:
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
  - `rowCount` detected at upload time: 225,745 rows
