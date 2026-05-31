This project is a Machine Learning based Cybersecurity tool that is designed to detect phishing URLs in real-time.

The purpose of this project is, instead of using traditional blacklisted websites to determine if a URL is malicious, it uses a Machine Learning model that has been trained on 651191 URLs, using a dataset acquired from Kaggle linked below.

The Machine Learning Model, that uses the Random Forest Classifier to identify suspicious patterns in URL structures.
This allows it to detect zero-day phishing attacks that have not been reported yet.

This project integrates Flask to create a web interface for better user interaction.

The Feature Extraction process:

    > IP address obfuscation checks.
    > Suspicious keyword analysis
    > Non-standard port detection
    > Sub-domain depth and entropy analysis.


Dataset used:

https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

The dataset consists of 651,191 URLs out of which 428,103 benign URLs and 96,457 defacement URLs, 94,111 phishing URLs and 32,520 malware URLs.



Old Detection Pipeline:

User inputs URL
       ↓
Basic format check (spaces, dots)
       ↓
Whitelist check ← WAS BROKEN (parsed "1,google.com" as a domain, never matched anything)
       ↓
Feature extraction — 14 URL-structure features
       ↓
Random Forest prediction
       ↓
Show: verdict + confidence score + hardcoded risk flags
      (no explanation of WHY the model decided)



The New Detection Pipeline:
User inputs URL
       ↓
Basic format check
       ↓
┌─────────────────────────────────────────┐
│ LAYER 1 — Whitelist (FIXED)             │
│ Properly parses rank,domain CSV format  │
│ Uses tldextract so mail.google.com      │
│ matches google.com correctly            │
│ → If trusted: exit immediately as SAFE  │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│ LAYER 2 — Live Threat Feeds (NEW)       │
│ threat_feeds.py                         │
│ Checks domain against OpenPhish +       │
│ URLhaus (thousands of confirmed         │
│ malicious domains, refreshed every 6h)  │
│ → If found: exit as MALICIOUS 100%      │
│   Model not consulted at all            │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│ LAYER 3 — ML Model (UPGRADED)           │
│ features.py → app.py                    │
│                                         │
│ Old: 14 features, Random Forest         │
│ New: 20 features, XGBoost               │
│                                         │
│ 6 new features added:                   │
│  • Subdomain depth                      │
│  • TLD risk score (.tk/.ml/.ga = bad)   │
│  • Brand lookalike score (paypa1.com)   │
│  • Digit ratio in domain (g00gle.com)   │
│  • Punycode / homograph detection       │
│  • URL path depth                       │
│                                         │
│ → Produces verdict + probability score  │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│ LAYER 4 — SHAP Explanation (NEW)        │
│ app.py → build_explanation()            │
│ Shows WHY the model decided:            │
│  "IP address as domain  ████████ risk"  │
│  "Uses HTTPS            ███ safe"       │
│  "Suspicious keywords   ██████ risk"    │
└─────────────────────────────────────────┘
       ↓
┌─────────────────────────────────────────┐
│ LAYER 5 — WHOIS Enrichment (NEW)        │
│ enrichment.py                           │
│ Looks up domain registration age        │
│ Cached for 24h so it's fast             │
│ → Appends flags like:                   │
│   "Domain is only 3 days old"           │
└─────────────────────────────────────────┘
       ↓
Show: verdict + confidence + risk flags
      + SHAP bar chart + enrichment flags