# 🛡️ AI-Based Cybersecurity Threat Detection — CIC-IDS2017

> An end-to-end machine learning pipeline for detecting, scoring, and triaging network intrusion threats using the CIC-IDS2017 dataset — built for the Cognizant Cybersecurity Hackathon.

---

## 📖 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Dataset](#dataset)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [Pipeline Walkthrough](#pipeline-walkthrough)
- [Team & Contributions](#team--contributions)
- [Folder Ownership Rules](#folder-ownership-rules)
- [Contribution Workflow (Git)](#contribution-workflow-git)
- [Roadmap](#roadmap)
- [Notes & Coordination](#notes--coordination)

---

## Overview

Network intrusions are constantly evolving, and static rule-based detection systems struggle to keep up with novel attack patterns. This project builds a **hybrid detection system** that combines:

- **Supervised classification models** trained on labeled attack traffic to catch known threat types
- **Unsupervised anomaly detection** to flag unusual traffic that doesn't match any known pattern (zero-day / novel threats)
- **Threat scoring and triage logic** to prioritize alerts by severity, so analysts aren't overwhelmed by noise
- **A dashboard** for visualizing traffic, flagged threats, and model performance in real time

The result is a pipeline that goes from raw network flow data → cleaned features → trained models → live threat scores → actionable, prioritized alerts.

## Key Features

- 🔄 **Automated preprocessing pipeline** for cleaning and transforming raw CIC-IDS2017 flow data
- ⚖️ **Class imbalance handling** to address the natural skew between benign and attack traffic
- 🤖 **Multiple supervised models** trained and compared for classification accuracy
- 🚨 **Anomaly detection module** for catching threats outside the labeled training distribution
- 📊 **Threat scoring & triage** to rank alerts by risk/urgency
- 📈 **Evaluation suite** with standard classification metrics (precision, recall, F1, confusion matrix)
- 🖥️ **Interactive dashboard** for exploring results and monitoring threats
- ☁️ **Cloud deployment ready**

## Architecture

```
                     ┌────────────────────┐
                     │   Raw Traffic Data  │
                     │   (CIC-IDS2017)      │
                     └──────────┬──────────┘
                                │
                     ┌──────────▼──────────┐
                     │   data_pipeline.py   │
                     │  (clean, transform)  │
                     └──────────┬──────────┘
                                │
                 ┌──────────────┼──────────────┐
                 │                              │
      ┌──────────▼──────────┐      ┌───────────▼───────────┐
      │   train_models.py    │      │   anomaly_scoring.py   │
      │ (supervised models)  │      │  (unsupervised / novel │
      │                       │      │   threat detection)    │
      └──────────┬──────────┘      └───────────┬───────────┘
                 │                              │
      ┌──────────▼──────────┐      ┌───────────▼───────────┐
      │  evaluate_models.py  │      │       triage.py         │
      │  (metrics & scoring) │      │ (prioritize/rank alerts)│
      └──────────┬──────────┘      └───────────┬───────────┘
                 │                              │
                 └──────────────┬───────────────┘
                                │
                      ┌─────────▼─────────┐
                      │      app.py        │
                      │  (dashboard / UI)   │
                      └────────────────────┘
```

## Project Structure

```
cognizant-uc16-final/
├── src/
│   ├── data_pipeline.py            # Data loading, cleaning, and feature preprocessing
│   ├── synthetic_generator.py      # Generates synthetic traffic samples for testing/augmentation
│   ├── test_synthetic_generator.py # Unit tests for the synthetic data generator
│   ├── train_models.py             # Trains supervised classification models
│   ├── evaluate_models.py          # Computes evaluation metrics on trained models
│   ├── anomaly_scoring.py          # Unsupervised anomaly detection and scoring logic
│   └── triage.py                   # Ranks and prioritizes flagged threats
├── data/
│   ├── raw/                        # Raw, untouched input data
│   └── processed/                  # Cleaned/feature-engineered output from the pipeline
├── models/                         # Serialized trained model files (one per contributor)
├── results/                        # Evaluation outputs, metrics, reports
├── docs/                           # Shared documentation (one file per topic)
├── app.py                          # Dashboard / application entry point
├── requirements.txt                # Python dependencies
└── README.md                       # You are here
```

## Dataset

This project uses **CIC-IDS2017**, a widely-used labeled intrusion detection dataset published by the Canadian Institute for Cybersecurity. It includes benign traffic alongside common real-world attack categories:

| Category | Examples |
|---|---|
| Denial of Service | DoS Hulk, DoS GoldenEye, DoS Slowloris |
| Distributed Denial of Service | DDoS |
| Brute Force | FTP-Patator, SSH-Patator |
| Web Attacks | SQL Injection, XSS, Brute Force |
| Infiltration | Internal network infiltration |
| Botnet | Botnet ARES |
| Port Scan | Reconnaissance traffic |

**Data placement:**
- Raw `.csv` flow files → `data/raw/`
- Pipeline-processed/cleaned output → `data/processed/`

## Setup & Installation

### Prerequisites
- Python 3.9+
- pip
- Git

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/Niyah18/cognizant-uc16-final.git
   cd cognizant-uc16-final
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv venv

   # Windows
   venv\Scripts\activate

   # macOS / Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Add the dataset**
   Place CIC-IDS2017 CSV files into `data/raw/`.

5. **Run the pipeline components as needed** (see [Usage](#usage))

## Usage

Run each stage of the pipeline independently, or run the full app for the dashboard view.

```bash
# 1. Preprocess raw data
python src/data_pipeline.py

# 2. Train supervised models
python src/train_models.py

# 3. Evaluate trained models
python src/evaluate_models.py

# 4. Run anomaly detection + threat scoring
python src/anomaly_scoring.py

# 5. Triage and rank flagged threats
python src/triage.py

# 6. Launch the dashboard
python app.py
```

## Pipeline Walkthrough

1. **`data_pipeline.py`** — Loads raw CIC-IDS2017 flow data, handles missing/malformed values, encodes categorical features, and outputs a clean dataset to `data/processed/`.
2. **`synthetic_generator.py`** — Generates synthetic traffic samples, useful for augmenting underrepresented attack classes or stress-testing the models.
3. **`train_models.py`** — Trains one or more supervised classifiers on the processed data to distinguish benign vs. attack traffic (and attack sub-types).
4. **`evaluate_models.py`** — Runs trained models against held-out test data and reports precision, recall, F1-score, and confusion matrices; results are saved to `results/`.
5. **`anomaly_scoring.py`** — Applies unsupervised techniques to score traffic that deviates from expected patterns, catching threats the supervised models weren't trained on.
6. **`triage.py`** — Combines classification output and anomaly scores to rank alerts by severity/urgency for analyst review.
7. **`app.py`** — Serves a dashboard that visualizes traffic, model results, and prioritized threats.

## Team & Contributions

| Member | Contribution Area | File(s) / Location |
|---|---|---|
| **Fathima** | Data preprocessing | `src/data_pipeline.py` |
| **Niyah** | Class imbalance handling, repository setup & structure | `src/`, repo administration |
| **Annet** | Supervised model development | `src/train_models.py` |
| **Ann ,Bhadra** | Supervised model development | `src/train_models.py` |
| **Sangeetha** | Supervised models & evaluation | `src/train_models.py`, `results/` |
| **Thejas** | Anomaly detection & threat scoring | `src/anomaly_scoring.py`, `src/triage.py` |
| **Sivatha** | Dashboard & cloud deployment | `app.py` |

## Folder Ownership Rules

To avoid conflicting edits across a team of seven, each shared folder has a designated owner or rule:

| Folder | Owner | Rule |
|---|---|---|
| `data/` | Fathima | Manages shared data files; others should not edit directly |
| `models/` | All model contributors | Each person adds **only their own** trained model file |
| `results/` | Sangeetha | Manages shared evaluation outputs |
| `docs/` | Everyone | Create a **new file per topic** — never edit someone else's file |

## Contribution Workflow (Git)

Every contributor follows the same branch → commit → PR → merge workflow:

```bash
# 1. Sync with the latest main
git pull origin main

# 2. Create your own branch
git checkout -b yourname-feature

# 3. Work only within your assigned file(s)

# 4. Stage only the files you changed (never `git add .`)
git add path/to/your-file.py

# 5. Commit with a tagged, descriptive message
git commit -m "[yourname] feat: short description"

# 6. Push your branch
git push -u origin yourname-feature

# 7. Open a pull request on GitHub against `main`
# 8. Get it reviewed, then merge
```

**Rules of the road:**
- Never use `git add .` for individual work — stage only what you changed.
- Always `git pull origin main` before starting new work.
- Each member works on their own branch and pushes with their own GitHub account.
- Never overwrite another member's files without coordinating first.
- Always open a pull request — don't push directly to `main`.

## Roadmap

- [ ] Finalize preprocessing pipeline
- [ ] Complete and compare supervised model candidates
- [ ] Tune anomaly detection thresholds
- [ ] Integrate triage scoring with dashboard
- [ ] Deploy dashboard to the cloud
- [ ] Add automated CI checks for pull requests

## Notes & Coordination

- **Thejas** (anomaly detection + scoring) and **Sivatha** (dashboard + deployment) have tightly coupled responsibilities — the dashboard consumes scoring output, so close coordination is needed between these two areas.
- **Annet**, **Ann ,Bhadra**, and **Sangeetha** all contribute to `train_models.py` — coordinate to keep experiments/functions clearly separated and avoid overwriting each other's work.
- Existing branches with duplicate copies of shared folders (`data`, `models`, `results`, `docs`) should be cleaned up before opening a pull request:
  ```bash
  git pull origin main
  git rm -r --cached data docs models results
  git add <only-your-assigned-file>
  git commit -m "[yourname] fix: keep only my assigned files"
  git push
  ```
