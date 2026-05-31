import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote
import tldextract



# Helper functions

def deep_decode(text: str) -> str:
    """
    Recursively URL-decodes a string until it stops changing.
    Defeats multi-layer percent-encoding obfuscation.
    """
    if not text:
        return ""
    decoded = unquote(text)
    while decoded != text:
        text    = decoded
        decoded = unquote(text)
    return decoded.lower()


def calculate_entropy(text: str) -> float:
    """
    Calculates Shannon entropy of a string.
    High entropy → highly random characters → typical of generated/obfuscated domains.
    """
    if not text:
        return 0.0
    length  = len(text)
    entropy = 0.0
    for count in Counter(text).values():
        p       = count / length
        entropy -= p * math.log2(p)
    return entropy


# Main Feature Extraction

def extract_features(url: str) -> dict | None:
    """
    Extracts a fixed set of numerical features from a URL string.

    Returns a dict of features, or None if the URL is empty / unparseable.

    """
    if not url or not isinstance(url, str):
        return None

    try:
        parsed    = urlparse(url)
        extracted = tldextract.extract(url)   # noqa: F841 (available for future features)
    except Exception as e:
        print(f"Failed to parse URL '{url}': {e}")
        return None

    features: dict = {}

    # --- Structure & Length ---
    features['url_length']      = len(url)
    features['hostname_length'] = len(parsed.netloc)
    features['path_length']     = len(parsed.path)
    features['url_entropy']     = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(parsed.netloc)

    # --- Special Character Counts ---
    features['dot_count']      = url.count('.')
    features['hyphen_count']   = url.count('-')
    features['at_count']       = url.count('@')
    features['question_count'] = url.count('?')
    features['percent_count']  = url.count('%')

    # --- Protocol ---
    features['is_https'] = 1 if parsed.scheme == 'https' else 0

    # --- Non-Standard Port Detection ---
    try:
        port = parsed.port
        features['is_non_std_port'] = 1 if (port and port not in (80, 443)) else 0
    except Exception:
        features['is_non_std_port'] = 0

    # --- IP Address Detection ---
    # Legitimate sites use domain names; phishing pages often use raw IPs.
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    features['has_ip_in_domain'] = 1 if re.search(ip_pattern, parsed.netloc) else 0

    # --- Suspicious Keyword Detection ---
    # Deep-decode first to catch obfuscated keywords like %6C%6F%67%69%6E → login
    decoded_url = deep_decode(url)
    suspicious_keywords = [
        'login', 'secure', 'account', 'update', 'banking',
        'confirm', 'verify', 'password', 'ebay', 'paypal',
        'signin', 'upi',
    ]
    features['suspicious_keyword_count'] = sum(
        1 for kw in suspicious_keywords if kw in decoded_url
    )

    return features
