# M3 URL Threat Classifier — Evaluation Report

Generated: 2026-09-12T17:51:10.827905+00:00


> ⚠️ **SYNTHETIC FIXTURE** — Metrics below are NOT production-representative.
> This dataset was generated from M2 rule logic.
> Replace with a real labeled dataset for production.

## Dataset

- **Version:** test-fixture-v1
- **Train:** 410
- **Validation:** 88
- **Test:** 89
- **Total:** 587

## Features

- Schema version: `v1`
- Feature count: 28
- Features: url_length, hostname_length, path_length, query_length, fragment_length, num_path_segments, num_query_params, num_subdomains, num_dots, num_hyphens, num_underscores, num_digits_in_host, num_special_chars_in_path, is_ip_address, is_ipv4, is_ipv6, subdomain_depth, is_suspicious_tld, is_punycode, is_https, is_http, has_non_standard_port, has_userinfo, has_encoded_chars, double_encoding_indicator, encoding_ratio, num_suspicious_keywords, num_credential_keywords_in_path

## Model Comparison (Validation Set)

| Model | Precision | Recall | F1 | ROC-AUC | FNR | FPR |
|-------|-----------|--------|----|---------|-----|-----|
| LogisticRegression **← selected** | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |
| RandomForest | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 |

## Selected Model

**LogisticRegression**  (highest recall on validation, tie-break F1)

## Classification Threshold

Threshold: **0.30**  
Optimised on validation set: maximise recall subject to precision ≥ 0.50.

## Test Set Metrics

| Metric | Value |
|--------|-------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 | 1.0000 |
| ROC-AUC | 1.0000 |
| False Negative Rate | 0.0000 |
| False Positive Rate | 0.0000 |

## Confusion Matrix (Test Set)

```
               Predicted
               Benign  Malicious
Actual Benign       37      0
Actual Malicious     0     52
```

## Limitations

- M3 is a **heuristic / statistical classifier** — not a complete phishing detector.
- Does not fetch, crawl, or verify URLs.
- Does not consult reputation databases.
- Trained on features extractable from the URL string alone — misses all content signals.
- Susceptible to adversarial URL construction that satisfies all extracted features.
- **Synthetic data**: model may have learned to replicate M2 rule logic rather than
  generalise to real-world phishing patterns.

## Potential Bias Sources

- TLD-based features assume English-language internet norms.
- Keyword list reflects common English phishing terminology.
- Benign baseline skews toward high-Alexa domains.

## Known Failure Cases

- Legitimate security-focused pages (e.g. `accounts.google.com/login`) may score medium.
- Novel phishing domains that avoid known suspicious TLDs/keywords.
- URL shorteners (the short URL itself may appear benign).