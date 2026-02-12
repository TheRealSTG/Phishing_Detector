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