# AI-Based Cybersecurity Threat Detection

**Use Case 16 · Cognizant Hackathon**

A network intrusion detection system built on CIC-IDS2017 that combines a supervised
classifier, an unsupervised anomaly detector, and a MITRE ATT&CK-mapped triage layer,
served through a live-replay Streamlit SOC dashboard with per-event SHAP explainability.

> **Scope note:** the dashboard replays held-out test traffic event-by-event to simulate
> near-real-time detection. It is **not** a live packet-capture system, and the MITRE
> ATT&CK mapping and severity/impact weights are this team's own design choices, not
> official ATT&CK submissions or industry-standard formulas. Both are called out
> explicitly in the UI.

---

## Table of contents

- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Setup](#setup)
- [Running the pipeline](#running-the-pipeline)
- [Running the dashboard](#running-the-dashboard)
- [How detection works](#how-detection-works)
- [Explainability](#explainability)
- [Model results](#model-results)
- [Design decisions](#design-decisions)
- [Known limitations](#known-limitations)
- [Docs index](#docs-index)

---

## What it does

Every replayed network flow is scored by two independent models and one lookup table,
merged into a single **threat score (0–100)** and a **severity band**
(Low / Medium / High / Critical):

1. **XGBoost classifier** — predicts one of 15 traffic categories (14 attack types + BENIGN)
   and returns `attack_confidence = 1 − P(BENIGN)`.
2. **Isolation Forest** — trained only on BENIGN traffic, returns a normalized anomaly
   score (0 = looks normal, 1 = highly anomalous) independent of any attack label.
3. **Category impact table** — a fixed severity weight per attack category
   (e.g. DDoS = 1.0, PortScan = 0.4), reflecting that not all attack types carry the
   same operational risk even at equal classifier confidence.

The three signals are combined into a single weighted threat score, mapped to a
MITRE ATT&CK technique, and surfaced with a per-event triage note and a
**"Why is this Critical?"** explainability panel (SHAP + a full breakdown of the
threat-score formula) so an analyst never has to take the score on faith.

## Architecture

The system is two pipelines: an **offline training pipeline** that runs once and
produces the saved model artifacts, and a **runtime inference pipeline** that runs
per replayed event inside the Streamlit dashboard, loading those artifacts and scoring
traffic live.

```
Pipeline A (offline, runs once)
  8 CIC-IDS2017 CSVs
    → clean + drop leakage columns (Flow ID, Source/Dest IP, Timestamp)
    → dedupe (2,830,743 → 2,522,362 rows)
    → fix mangled Web Attack label text
    → class-aware downsample of BENIGN to a 3:1 ratio
    → stratified 80/20 split
    → impute Inf/NaN (medians fit on train only, applied to test)
    → lock data_contract.json (78 feature columns + 15 class labels)
    → train Logistic Regression / Random Forest / XGBoost (class-weighted)
    → select best model by macro F1 + rare-class recall (XGBoost wins)
    → fit Isolation Forest on BENIGN-only training rows
    → lock anomaly normalization anchors (1st/99th percentile of BENIGN scores)
    → lock category_impact.json (manual severity weight per category)
  → saved artifacts in models/ and data/processed/

Pipeline B (runtime, Streamlit dashboard, per event)
  Sample one row from test.parquet (ground-truth label kept aside, never given to the model)
    → extract & reshape into a single-row feature vector (data_contract.json column order)
    → feed identically into two independent models:
         Isolation Forest → anomaly_score (0–1)
         XGBoost          → attack_category, confidence, attack_confidence, 15-class probs
    → look up category_impact.json for the predicted category
    → merge: threat_score = clip(100 × (0.50·attack_confidence + 0.30·anomaly_score + 0.20·category_impact), 0, 100)
    → map threat_score → severity (Low/Medium/High/Critical)
    → build triage note (MITRE ATT&CK technique + recommended action + top drivers)
    → append to session state → render on dashboard
    → after a configurable delay, repeat for the next row
```

A full data-flow diagram (with every numbered step) was produced separately for this
project — see `nids-architecture-diagram.png` if you have it alongside this repo.

## Repository layout

```
.
├── app.py                          # Streamlit SOC dashboard (entry point)
├── src/
│   ├── data_pipeline.py            # Pair A: clean → dedupe → sample → split → impute
│   ├── train_models.py             # Pair B: train LR/RF/XGBoost, select best, serialize
│   ├── anomaly_scoring.py          # Pair C: fit Isolation Forest, lock normalization + threat formula
│   ├── evaluate_models.py          # Confusion matrix + per-class report generation
│   └── triage.py                   # SHAP explainability + MITRE ATT&CK mapping + triage notes
├── data/
│   ├── raw/                        # Original CIC-IDS2017 CSVs (not committed — see Setup)
│   └── processed/
│       ├── data_contract.json      # Locked feature columns, classes, random seed
│       ├── train.parquet           # Generated by data_pipeline.py
│       └── test.parquet            # Generated by data_pipeline.py
├── models/                         # Generated by train_models.py / anomaly_scoring.py
│   ├── logisticregression_model.joblib
│   ├── randomforest_model.joblib
│   ├── xgboost_model.joblib
│   ├── isolation_forest_model.joblib
│   ├── label_encoder.joblib
│   ├── model_metadata.json         # Per-model metrics + which model was selected and why
│   ├── anomaly_normalization.json  # Locked p1/p99 anchors for anomaly score scaling
│   └── category_impact.json        # Manual severity weight per attack category
├── results/
│   ├── confusion_matrix.png
│   ├── per_class_recall.csv
│   └── classification_reports.json
├── deploy_package/                 # Self-contained copy of app.py + src/ + models/ for deployment
└── docs/
    ├── dataset.md                  # Cleaning pipeline + final class distribution
    ├── decisions.md                # Why each design choice was made
    ├── interfaces.md               # Frozen contracts between pipeline components
    └── pair_c_report.md            # Isolation Forest + threat-scoring evaluation, Q&A prep
```

## Setup

Requires **Python 3.10+**.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install streamlit pandas numpy scikit-learn xgboost joblib shap plotly matplotlib seaborn pyarrow
```

> There's no committed `requirements.txt` yet — the list above covers every import used
> across `src/` and `app.py`. Consider freezing it with `pip freeze > requirements.txt`
> once your environment is finalized.

### Getting the dataset

The raw CIC-IDS2017 CSVs are **not committed** to this repo (dataset size). Download the
8 CSVs from the [CIC-IDS2017 dataset page](https://www.unb.ca/cic/datasets/ids-2017.html)
and place them in `data/raw/`. The pipeline reads them with `cp1252` encoding, which
matches the original files.

If you only want to run the **dashboard** and already have the generated artifacts
(`data/processed/*.parquet`, `models/*.joblib`), you can skip straight to
[Running the dashboard](#running-the-dashboard) — `deploy_package/` ships a
self-contained copy of everything the app needs.

## Running the pipeline

Run these in order from the project root. Each step reads the previous step's output.

```bash
# 1. Clean, dedupe, sample, split, impute — produces data/processed/*.parquet + data_contract.json
python src/data_pipeline.py

# 2. Train LR / RF / XGBoost, select the best by macro F1 + rare-class recall
python src/train_models.py

# 3. Fit Isolation Forest on BENIGN-only data, lock normalization anchors + category impact
python src/anomaly_scoring.py

# 4. Generate confusion matrix + per-class report for the Model Evaluation tab
python src/evaluate_models.py
```

All four steps are deterministic given `random_seed: 42` in `data_contract.json`.

## Running the dashboard

```bash
streamlit run app.py
```

In the sidebar:

- **Number of events to replay** — how many test-set rows to sample per run (10–200)
- **Delay between events** — pacing, so the "live feed" is watchable rather than instant
- **Sample seed** — controls which rows get sampled, for reproducible demo runs
- **Start Simulation** — samples rows from `test.parquet` and scores them one at a time
- **Reset** — clears the running session state

The dashboard has four tabs:

| Tab | Contents |
|---|---|
| 🔴 Live Feed | Scrolling table of every scored event, a "pick an event" explain panel for any High/Critical event, and a threat-score timeline |
| 📊 Analytics | Attack category breakdown and severity distribution, aggregated across the run |
| 🧭 Threat Intel | This team's MITRE ATT&CK mapping table + the generated triage note for every High/Critical event |
| 📈 Model Evaluation | Static model comparison table, confusion matrix, and per-class precision/recall/F1 from the last `evaluate_models.py` run |

## How detection works

Every event goes through the same four-stage pipeline (`app.py::process_event`):

1. **Feature extraction** — the row's 78 feature columns (from `data_contract.json`) are
   pulled out as a single-row DataFrame and cast to `float`. Ground-truth `Label` is kept
   aside for display only — it is never given to either model.
2. **Anomaly scoring** — `IsolationForest.decision_function()` (higher = more normal, by
   sklearn convention) is inverted and rescaled using locked BENIGN-training percentile
   anchors: `anomaly_score = clip((p99 − raw) / (p99 − p1), 0, 1)`. Anchors used in this
   run: `p1 = -0.1499`, `p99 = 0.1808`.
3. **Classification** — XGBoost returns a probability for all 15 classes;
   `attack_category` is the argmax, `confidence` is that class's probability, and
   `attack_confidence = 1 − P(BENIGN)`.
4. **Threat scoring** — the two model outputs plus a fixed category-impact weight are
   merged into one score:

```text
threat_score = clip(
    100 × (0.50 × attack_confidence + 0.30 × anomaly_score + 0.20 × category_impact),
    0, 100
)
```

| Threat score | Severity |
|---:|---|
| 0–25 | Low |
| 25–50 | Medium |
| 50–75 | High |
| 75–100 | Critical |

**Why combine a classifier and an anomaly detector?** They catch different things.
In the team's own sanity check, a PortScan event scored a *low* anomaly score (0.063 —
it looked close to normal traffic to Isolation Forest) but the classifier identified it
as PortScan with high confidence, correctly producing a High overall score. Relying on
anomaly detection alone would have under-scored it; relying on the classifier alone
gives no signal for attack patterns the model has never seen. See
[`docs/pair_c_report.md`](docs/pair_c_report.md) for the full write-up and more examples.

## Explainability

The **"Why is this Critical?"** panel (available for any High/Critical event in the Live
Feed tab) answers two different questions, deliberately kept separate:

- **"Why did the classifier predict this category?"** — answered by **SHAP**
  (`TreeExplainer`, per-instance, top 3 contributing features with direction). Falls back
  to global feature importance if SHAP fails or the model isn't tree-based, so a broken
  explainer never takes down the live dashboard.
- **"Why is the severity what it is?"** — answered by a full breakdown of the
  threat-score formula: each of the three weighted components (classifier confidence,
  anomaly score, category impact) shown with its raw value and point contribution,
  summing to the final score.

This separation matters because SHAP explains the *classification*, not the *severity* —
conflating the two would misrepresent what SHAP is actually telling you.

The triage note itself (MITRE ATT&CK technique + recommended action) is generated by
`src/triage.py::build_triage_note` — pure template formatting over real feature-importance
and category metadata, no free-text generation.

## Model results

Three supervised models were trained with class weights; XGBoost was selected as the
final classifier by macro F1 + rare-class recall (primary), weighted F1 (secondary),
training time as a tiebreaker.

| Model | Macro F1 | Weighted F1 | Rare-class recall | Train time |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.545 | 0.900 | 0.911 | 677.6s |
| Random Forest | 0.890 | 0.998 | 0.914 | 136.2s |
| **XGBoost (selected)** | **0.914** | **0.998** | **0.921** | 262.0s |

XGBoost per-class highlights on the held-out test set (340,703 rows):

| Class | Precision | Recall | F1 | Support |
|---|---:|---:|---:|---:|
| BENIGN | 0.9999 | 0.9988 | 0.9993 | 255,527 |
| DDoS | 0.9998 | 0.9999 | 0.9998 | 25,603 |
| PortScan | 0.9928 | 0.9993 | 0.9961 | 18,164 |
| Bot | 0.751 | 0.987 | 0.853 | 391 |
| Web Attack - Brute Force | 0.740 | 0.728 | 0.734 | 294 |
| Web Attack - XSS | 0.392 | 0.431 | 0.410 | 130 |
| Heartbleed | 1.0 | 1.0 | 1.0 | 2 |
| Infiltration | 1.0 | 1.0 | 1.0 | 7 |
| Web Attack - SQL Injection | 0.75 | 0.75 | 0.75 | 4 |

> Heartbleed, Infiltration, and Web Attack - SQL Injection have single-digit test
> support — treat their perfect/near-perfect scores as indicative, not statistically
> robust. See [`docs/dataset.md`](docs/dataset.md) for the full class distribution.

Isolation Forest (unsupervised — accuracy isn't the right metric, so evaluated on
separation instead), trained on 1,022,107 BENIGN-only rows:

| Metric | Value |
|---|---:|
| Known-BENIGN mean anomaly score | 0.161 |
| Known-attack mean anomaly score | 0.535 |
| ROC-AUC (BENIGN vs attack) | 0.799 |
| PR-AUC (BENIGN vs attack) | 0.625 |
| Detection rate @ 0.5 threshold | 58.9% |
| False-alarm rate @ 0.5 threshold | 8.6% |

Full evaluation write-up, methodology, and a "why not anomaly detection alone" discussion
are in [`docs/pair_c_report.md`](docs/pair_c_report.md).

## Design decisions

The reasoning behind every non-obvious choice — why supervised + unsupervised, why
Isolation Forest specifically, why percentile-based normalization anchors instead of
min/max, why the 50/30/20 threat-score weighting, why class-aware sampling happens
*before* the train/test split — is documented in
[`docs/decisions.md`](docs/decisions.md). Two points worth surfacing here:

- **Sampling before split is intentional.** BENIGN was downsampled to a 3:1 ratio against
  attack rows *before* the stratified split, so the test set reflects that reduced BENIGN
  ratio rather than natural traffic proportions. This is a locked design choice, not an
  oversight — documented so it doesn't read as a mistake under review.
- **Leakage prevention.** `Flow ID`, source/destination IP, and `Timestamp` are dropped
  before training so the models learn behavioral patterns, not identifiers. Imputation
  medians are fit on train only and applied to test, so no test-set statistics leak into
  training.

## Known limitations

- **Simulation, not live capture.** The dashboard replays held-out test rows; it does not
  ingest live network traffic. This was an explicit scope decision to allow a full,
  demonstrable pipeline within the hackathon timeline.
- **Self-authored severity model.** MITRE ATT&CK mappings, category-impact weights, and
  the threat-score formula (50/30/20) are this team's own judgment calls, not certified
  ATT&CK submissions or an industry-standard scoring formula.
- **Rare-class metrics are low-confidence.** A handful of attack categories (Heartbleed,
  Infiltration, SQL Injection) have fewer than 40 total samples in the entire dataset —
  their precision/recall numbers should be read as indicative only.
- **Weak classes.** Web Attack - XSS (F1 0.41) and Web Attack - Brute Force (F1 0.73)
  are the model's clearest blind spots and would be the first place to focus further
  feature engineering or additional training data.
- **Isolation Forest detection rate.** At the fixed 0.5 threshold, Isolation Forest alone
  catches 58.9% of attacks with an 8.6% false-alarm rate — this is by design meant to be
  a secondary signal, not a standalone detector (see [Model results](#model-results)).

## Docs index

| Doc | Covers |
|---|---|
| [`docs/dataset.md`](docs/dataset.md) | Cleaning pipeline, dedup counts, label normalization, final class distribution |
| [`docs/decisions.md`](docs/decisions.md) | Why each modeling and scoring decision was made |
| [`docs/interfaces.md`](docs/interfaces.md) | Frozen function-level contracts between pipeline components (e.g. why `.iloc[[0]]` not `.iloc[0]`) |
| [`docs/pair_c_report.md`](docs/pair_c_report.md) | Isolation Forest evaluation, threat-scoring rationale, anticipated Q&A |
