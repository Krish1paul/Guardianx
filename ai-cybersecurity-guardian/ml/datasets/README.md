# ML Datasets

This directory manages URL threat classifier training data.

## ⚠️ Dataset Status

**No production dataset is bundled with this repository.**

A small **synthetic fixture** (`fixtures/sample_urls.csv`) is included for
pipeline validation only. It is explicitly NOT production-representative.
Metrics produced from this fixture must NOT be used to make security claims.

---

## Expected Format

All datasets must be CSV files with at minimum these two columns:

```
url,label
https://example.com/,0
http://192.168.1.1/login,1
```

| Column | Type | Values |
|--------|------|--------|
| `url` | string | Any valid http:// or https:// URL |
| `label` | integer | `0` = benign, `1` = malicious/phishing |

Additional columns (e.g. `source`, `date_added`, `category`) are preserved
but ignored during training.

---

## Directory Layout

```
ml/datasets/
├── README.md           ← this file
├── fixtures/
│   └── sample_urls.csv ← synthetic test fixture (committed, small, labelled)
├── raw/                ← GITIGNORED — place downloaded datasets here
└── processed/          ← GITIGNORED — preprocessed splits cached here
```

`raw/` and `processed/` are listed in `.gitignore`.
**Never commit raw datasets or personally identifiable URL data to Git.**

---

## Recommended Real Datasets

| Dataset | Source | Notes |
|---------|--------|-------|
| PhishTank | https://phishtank.org/developer_info.php | Free, CC0, requires registration |
| ISCX URL 2016 | https://www.unb.ca/cic/datasets/url-2016.html | Academic use |
| Kaggle Phishing URLs | https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset | Kaggle account required |
| Alexa Top 1M | http://s3.amazonaws.com/alexa-static/top-1m.csv.zip | Benign baseline (validate before use) |

Before using any dataset:
1. Verify the license permits your use case.
2. Document the collection date (URLs go stale).
3. Check class balance — phishing datasets are often highly imbalanced.
4. Validate a sample manually.

---

## Adding a Real Dataset

1. Download CSV to `ml/datasets/raw/your_dataset.csv`
2. Ensure it has `url` and `label` columns (or rename)
3. Run the training script pointing to the new file:

```bash
python3 -m ml.training.train_url_model \
    --dataset ml/datasets/raw/your_dataset.csv \
    --dataset-version your_dataset_v1
```

4. Check evaluation report in `ml/evaluation/reports/`
5. If metrics are acceptable, copy model artifact to `ml/models/url_model_v1/`

---

## Privacy

URLs can contain personally identifiable information (search queries, tokens,
email addresses in query strings). Do not commit raw URL datasets containing
user PII to version control.

---

## Limitations of the Synthetic Fixture

The synthetic fixture generates:
- Benign URLs: well-formed `https://` URLs on common TLDs with realistic paths
- Malicious-pattern URLs: IP hostnames, punycode, suspicious TLDs, userinfo,
  credential path keywords, HTTP-only — drawn from the M2 risk rule set

**This is a circular construction**: the fixture is generated to match the M2
rules, so models trained on it will likely learn to replicate M2 rule behaviour.
A real diverse dataset is essential for production deployment.
