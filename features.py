"""
features.py
-----------
Extracts purely structural / lexical features from a URL string.
All operations are in-memory with no network calls, so this is fast
enough to run at training time across 600k+ URLs.
Feature count: 25
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote

import tldextract
from rapidfuzz import distance as fuzz_distance

# Constants
BRAND_TARGETS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'hsbc',
    'sbi', 'hdfc', 'icici', 'yahoo', 'outlook', 'office365',
]
TLD_RISK_MAP = {
    # High risk (score 2)
    'tk': 2, 'ml': 2, 'ga': 2, 'cf': 2, 'gq': 2,
    'top': 2, 'xyz': 2, 'work': 2, 'date': 2, 'racing': 2,
    'download': 2, 'stream': 2, 'accountant': 2, 'loan': 2,
    'click': 2, 'link': 2, 'win': 2, 'men': 2, 'party': 2,
    'cyou': 2, 'icu': 2, 'buzz': 2,
    # Elevated risk (score 1)
    'info': 1, 'biz': 1, 'online': 1, 'site': 1, 'tech': 1,
    'store': 1, 'club': 1, 'live': 1, 'space': 1, 'fun': 1,
}
COMMON_TLDS = {'com', 'net', 'org', 'gov', 'edu', 'co', 'io', 'uk', 'de', 'fr'}
SUSPICIOUS_KEYWORDS = [
    'login', 'secure', 'account', 'update', 'banking',
    'confirm', 'verify', 'password', 'ebay', 'paypal',
    'signin', 'upi', 'wallet', 'auth', 'credential',
]
VOWELS = set('aeiou')

# Helpers
def deep_decode(text: str) -> str:
    """Recursively URL-decodes until stable. Defeats multi-layer obfuscation."""
    if not text:
        return ""
    decoded = unquote(text)
    while decoded != text:
        text    = decoded
        decoded = unquote(text)
    return decoded.lower()

def calculate_entropy(text: str) -> float:
    """Shannon entropy — high value means highly random/obfuscated string."""
    if not text:
        return 0.0
    length  = len(text)
    entropy = 0.0
    for count in Counter(text).values():
        p        = count / length
        entropy -= p * math.log2(p)
    return entropy

def brand_lookalike_score(domain: str) -> int:
    """Min Levenshtein distance from domain to any known brand. Low = suspicious."""
    if not domain:
        return 99
    return min(
        fuzz_distance.Levenshtein.distance(domain.lower(), brand)
        for brand in BRAND_TARGETS
    )

# Main Feature Extraction
def extract_features(url: str) -> dict | None:
    """
    Extracts 25 numerical features from a URL string.
    Returns a feature dict or None if the URL is unparseable.
    No network calls — safe to run at training time on large datasets.
    """
    if not url or not isinstance(url, str):
        return None

    try:
        parsed    = urlparse(url)
        extracted = tldextract.extract(url)
    except Exception as e:
        print(f"Failed to parse URL '{url}': {e}")
        return None

    features: dict = {}

    # 1. Length & structure
    features['url_length']      = len(url)
    features['hostname_length'] = len(parsed.netloc)
    features['path_length']     = len(parsed.path)

    # 2. Entropy
    features['url_entropy']    = calculate_entropy(url)
    features['domain_entropy'] = calculate_entropy(parsed.netloc)

    # 3. Special character counts
    features['dot_count']      = url.count('.')
    features['hyphen_count']   = url.count('-')
    features['at_count']       = url.count('@')
    features['question_count'] = url.count('?')
    features['percent_count']  = url.count('%')

    # 4. Protocol & port
    features['is_https'] = 1 if parsed.scheme == 'https' else 0

    try:
        port = parsed.port
        features['is_non_std_port'] = 1 if (port and port not in (80, 443)) else 0
    except Exception:
        features['is_non_std_port'] = 0

    # 5. IP address in domain
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    features['has_ip_in_domain'] = 1 if re.search(ip_pattern, parsed.netloc) else 0

    # 6. Suspicious keywords
    decoded_url = deep_decode(url)
    features['suspicious_keyword_count'] = sum(
        1 for kw in SUSPICIOUS_KEYWORDS if kw in decoded_url
    )

    # 7. Subdomain depth
    subdomain = extracted.subdomain or ''
    features['subdomain_depth'] = len(subdomain.split('.')) if subdomain else 0

    # 8. TLD risk score
    tld = extracted.suffix.split('.')[-1].lower() if extracted.suffix else ''
    features['tld_risk_score'] = TLD_RISK_MAP.get(tld, 0)

    # 9. Brand lookalike score
    features['brand_lookalike_score'] = brand_lookalike_score(extracted.domain)

    # 10. Digit ratio in domain
    domain_str  = extracted.domain or ''
    digit_count = sum(1 for c in domain_str if c.isdigit())
    features['digit_ratio_in_domain'] = (
        digit_count / len(domain_str) if domain_str else 0.0
    )

    # 11. Punycode / homograph detection
    features['has_punycode'] = 1 if 'xn--' in parsed.netloc.lower() else 0

    # 12. Path depth
    path_parts = [p for p in parsed.path.split('/') if p]
    features['path_depth'] = len(path_parts)

    # 13. TLD embedded in path/subdomain
    #     paypal.com.verify.tk — 'com' appears inside subdomain
    full_path_and_sub = (parsed.path + '.' + subdomain).lower()
    tld_in_path = any(
        f'.{t}.' in full_path_and_sub or full_path_and_sub.startswith(f'{t}.')
        for t in COMMON_TLDS
    )
    features['has_tld_in_path'] = 1 if tld_in_path else 0

    # 14. Query string length & parameter count
    features['query_string_length'] = len(parsed.query)
    features['num_query_params']    = (
        len(parsed.query.split('&')) if parsed.query else 0
    )

    # 15. Digit-to-letter ratio across the full URL
    letters      = sum(1 for c in url if c.isalpha())
    digits_total = sum(1 for c in url if c.isdigit())
    features['digit_letter_ratio'] = (
        digits_total / (letters + digits_total)
        if (letters + digits_total) > 0 else 0.0
    )

    # 16. Special characters in domain (beyond hyphens and dots)
    features['special_chars_in_domain'] = sum(
        1 for c in parsed.netloc
        if not c.isalnum() and c not in '.-:'
    )

    # 17. Vowel ratio in domain name
    #     Human-readable domains: ~38-45% vowels
    #     Algorithm-generated domains (zui9o9, xkqpfv): very low vowel ratio
    domain_letters = [c for c in domain_str.lower() if c.isalpha()]
    features['vowel_ratio'] = (
        sum(1 for c in domain_letters if c in VOWELS) / len(domain_letters)
        if domain_letters else 0.0
    )

    return features
