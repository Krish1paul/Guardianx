# M3 — ML Pipeline Documentation

## Overview

M3 replaces the M2 deterministic rule engine with a supervised ML classifier
for URL threat detection. The pipeline is designed to be:

- **Reproducible** — fixed seed (42), deterministic splits, versioned artifacts
- **Explainable** — feature importances mapped to typed security reasons
- **Safe** — no network I/O, trusted model path, schema validation
- **Backward-compatible** — M2 `rule-v1` historical scans are never modified

---

## Architecture

```
POST /api/v1/analyze/url
          │
          ▼
URLAnalyzerService.analyze()
          │
   1. validate_url()         ← M2 url_utils (unchanged)
   2. normalize_url()        ← M2 url_utils (unchanged)
   3. hash_url()             ← M2 url_utils (unchanged)
   4. url_features.extract() ← M2 URLFeatures (unchanged)
          │
          ▼
   URLFeatures (30+ fields)
          │
          ▼
5. url_feature_vector.features_to_vector()
          │
   27-column float vector
          │
          ▼
6. URLInferenceEngine.run()  ← M3 ML inference
          │
   P(malicious) → score [0-100]
          │
   URLExplainer.explain()
          │
          ▼
   URLRiskResult(score, classification, reasons, analyzer_version="ml-v1")
          │
          ▼
   url_scans table (DB)
          │
          ▼
   URLScanResponse (API response)
```

---

## Components

### `ml/features/url_feature_vector.py`

Defines `FEATURE_NAMES` — the stable ordered list of numeric feature columns.
`features_to_vector(f: URLFeatures) -> list[float]` maps any `URLFeatures`
instance to the same vector in training and inference.

**Feature schema version**: `v1` (28 features)

| Category | Features |
|----------|----------|
| Structural | `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length`, `num_path_segments`, `num_query_params`, `num_subdomains`, `num_dots`, `num_hyphens`, `num_underscores`, `num_digits_in_host`, `num_special_chars_in_path` |
| Host/Domain | `is_ip_address`, `is_ipv4`, `is_ipv6`, `subdomain_depth`, `is_suspicious_tld`, `is_punycode` |
| Security | `is_https`, `is_http`, `has_non_standard_port`, `has_userinfo`, `has_encoded_chars`, `double_encoding_indicator`, `encoding_ratio` |
| Lexical | `num_suspicious_keywords`, `num_credential_keywords_in_path` |

> [!IMPORTANT]
> **Any change to `FEATURE_NAMES` must bump `FEATURE_SCHEMA_VERSION`.**
> The inference engine validates this at load time and falls back to `rule-v1` on mismatch.

---

### `ml/preprocessing/url_dataset.py`

Loads, validates, deduplicates, and splits URL datasets.

```python
from ml.preprocessing.url_dataset import load_and_split

split = load_and_split("ml/datasets/raw/phishtank.csv", seed=42)
# split.train, split.val, split.test — each is list[tuple[str, int]]
```

**Split ratios**: 70% train / 15% val / 15% test (stratified).

**Deduplication policy**:
- Exact duplicate (same URL, same label) → keep first
- Conflicting labels (same URL, different labels) → drop both, log WARNING
- Deduplication runs on *normalized* URLs before splitting to prevent data leakage

---

### `ml/training/train_url_model.py`

Training script. Run from the project root:

```bash
# Default (synthetic fixture):
python3 -m ml.training.train_url_model

# Real dataset:
python3 -m ml.training.train_url_model \
    --dataset ml/datasets/raw/phishtank_urls.csv \
    --dataset-version phishtank_2024_v1
```

**Model selection criterion**: highest **recall** on the validation set (malicious class),
tie-broken by F1. False negatives (missed malicious URLs) are more dangerous than
false positives in a security context.

**Models evaluated**:
| Model | Notes |
|-------|-------|
| Logistic Regression | Fast baseline, interpretable coefficients |
| Random Forest | Primary model (installed by default) |
| XGBoost | Evaluated if installed (`pip install xgboost`) |

---

### `ml/evaluation/evaluate.py`

```python
from ml.evaluation.evaluate import evaluate_model, find_best_threshold

result = evaluate_model(model, X_test, y_test, threshold=0.5)
print(result.summary())
# threshold=0.50  precision=0.923  recall=0.961  f1=0.942  ...

best_t = find_best_threshold(model, X_val, y_val, min_precision=0.5)
```

**Metrics reported**: accuracy, precision, recall, F1, ROC-AUC, FPR, FNR, confusion matrix.

---

### `ml/inference/url_inference.py` — M3 Swap Point

```python
from ml.inference.url_inference import URLInferenceEngine

engine = URLInferenceEngine()
result = engine.run(features)
# result.analyzer_version == "ml-v1" (if ML model loaded)
# result.analyzer_version == "rule-v1" (if fallback fired)
```

**Fallback strategy (Option B)**: If the ML model artifact is missing, corrupt, or has
a schema version mismatch, the engine falls back to the M2 rule engine.
The result has `analyzer_version="rule-v1"` — it is NEVER mislabelled as `ml-v1`.
A `WARNING` log is emitted.

**Risk score mapping**:
```
P(malicious) × 100 → risk_score [0, 100]
```

**Classification thresholds** (unchanged from M2):
```
0  – 24  → LOW_RISK
25 – 49  → MEDIUM_RISK
50 – 74  → HIGH_RISK
75 – 100 → CRITICAL
```

---

### `ml/inference/url_explainer.py`

```python
from ml.inference.url_explainer import URLExplainer

explainer = URLExplainer.from_pipeline(model)
reasons = explainer.explain(features, probability=0.87)
```

Generates `list[RiskReason]` using the existing `ReasonCode` and `Severity` enums
from `url_risk_engine.py`. No SHAP dependency required.

**Supported model types**: RandomForest, XGBoost (via `feature_importances_`),
LogisticRegression (via absolute coefficient magnitudes).

---

## Model Artifacts

Saved to `ml/models/url_model_v1/`:

| File | Description |
|------|-------------|
| `model.pkl` | Trained sklearn Pipeline (scaler + classifier) |
| `metadata.json` | Training config, metrics, dataset info |
| `feature_schema.json` | Feature names and schema version |

> [!CAUTION]
> `model.pkl` is in `.gitignore`. Do NOT commit model binaries to version control.
> Store them in a model registry (MLflow, S3, etc.) for production.

---

## Using a Real Dataset

1. Download a labeled URL dataset (see `ml/datasets/README.md` for sources)
2. Ensure CSV format: `url,label` (0=benign, 1=malicious)
3. Run training:
   ```bash
   python3 -m ml.training.train_url_model \
       --dataset ml/datasets/raw/your_dataset.csv \
       --dataset-version your_dataset_v1
   ```
4. Review `ml/evaluation/reports/url_model_v1.md`
5. If metrics are acceptable, deploy the new `model.pkl`

---

## Security Constraints

| Constraint | Enforced By |
|-----------|-------------|
| No network I/O during inference | Module has no HTTP client imports; SSRF tests in `test_url_model_security.py` |
| Fixed trusted model path | `_MODEL_DIR` is hard-coded; path traversal check via `os.path.realpath()` |
| Schema validation at load | `feature_schema.json` compared against `FEATURE_SCHEMA_VERSION` and `FEATURE_NAMES` |
| Corrupt model → fallback | `joblib.load()` wrapped in try/except; falls back to rule-v1 |
| No subprocess calls | SSRF tests verify |
| Metrics not fabricated | Synthetic fixture clearly labelled; report includes caveat |

---

## Limitations and Known Failure Cases

> [!WARNING]
> **The synthetic fixture model is NOT production-ready.** It learns to replicate M2
> rule logic. Replace with a real labeled dataset before production deployment.

- Does not fetch, crawl, or verify URL content
- Does not consult reputation databases (Google Safe Browsing, VirusTotal, etc.)
- Features are extractable from the URL string alone — misses all page content signals
- Susceptible to adversarial URL construction (e.g. HTTPS + clean TLD + no keywords)
- Keyword list reflects English-language phishing patterns — may miss non-English campaigns
- URL shorteners appear benign (the short URL itself has no structural signals)
- Legitimate security pages (e.g. `accounts.google.com/login`) may score MEDIUM

---

## Evaluation Report

After running the training script, a detailed report is written to:
`ml/evaluation/reports/url_model_v1.md`

This includes:
- Model comparison table (precision, recall, F1, ROC-AUC, FNR, FPR)
- Selected model and rationale
- Classification threshold
- Test set confusion matrix
- Limitations and bias sources

---

## Upgrading the Model (Future)

To replace with a new model version:

1. Train with a real dataset:
   ```bash
   python3 -m ml.training.train_url_model \
       --dataset ml/datasets/raw/real_dataset.csv \
       --dataset-version real_v1
   ```
2. Review the evaluation report
3. Place new artifact in `ml/models/url_model_v1/` (or a new versioned directory)
4. If using a new directory, update `_MODEL_DIR` in `ml/inference/url_inference.py`
5. Restart the application
6. Bump `FEATURE_SCHEMA_VERSION` if any features changed

---

## Testing

```bash
cd backend

# Run all tests (includes M0-M2 + M3)
python3 -m pytest tests/ -v

# Run only M3 tests
python3 -m pytest tests/test_url_feature_vector.py \
    tests/test_url_dataset.py \
    tests/test_url_training.py \
    tests/test_url_evaluation.py \
    tests/test_url_inference_ml.py \
    tests/test_url_explainability.py \
    tests/test_url_model_security.py -v
```

---

## M7 — Message Phishing ML Model (`message-v1`)

M7 introduces an NLP classification model for email/message phishing detection:

### Architecture
- **Dataset**: `ml/datasets/synthetic_messages.csv` (labeled with urgency, financial, credential, suspension indicators).
- **Pipeline**: Scikit-Learn `Pipeline([('tfidf', TfidfVectorizer(max_features=500, ngram_range=(1,2))), ('clf', LogisticRegression(class_weight='balanced'))])`.
- **Artifacts Directory**: `ml/models/message_model_v1/`
  - `model.pkl`: Serialized Scikit-Learn pipeline.
  - `metadata.json`: Records pipeline parameters, dataset details, test metrics, and the cryptographic `sha256` digest of `model.pkl`.
  - `feature_schema.json`: Input schema and feature dictionary.

### Cryptographic Verification & Fallback
- `MessageInferenceEngine` computes the SHA-256 digest of `model.pkl` upon initialization.
- If the digest does not match `metadata.json` or if the file is absent/unreadable, it activates the deterministic heuristic fallback (`fallback_heuristic_score`) without throwing an unhandled exception or crashing the server.
- Top contributing terms are extracted using model coefficients multiplied by TF-IDF weights, providing explainability in the API response.

