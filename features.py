"""
features.py

Extracts purely structural / lexical features from a URL string.
All operations are in-memory with no network calls, so this is fast
enough to run at training time across 600k+ URLs.
"""

import re
import math
from collections import Counter
from urllib.parse import urlparse, unquote
import tldextract
from rapidfuzz import distance as fuzz_distance

# Brand lookalike list — top targets for phishing impersonation
BRAND_TARGETS = [
    'paypal', 'google', 'apple', 'microsoft', 'amazon', 'netflix',
    'facebook', 'instagram', 'twitter', 'linkedin', 'dropbox',
    'bankofamerica', 'wellsfargo', 'chase', 'citibank', 'hsbc',
    'sbi', 'hdfc', 'icici', 'yahoo', 'outlook', 'office365',
]

# High-risk TLDs — free / abused / frequently used for phishing
# Scored 0 (neutral), 1 (elevated), 2 (high risk)
TLD_RISK_MAP = {
    # High risk (score 2) — free TLDs, heavily abused
    'tk': 2, 'ml': 2, 'ga': 2, 'cf': 2, 'gq': 2,
    'top': 2, 'xyz': 2, 'work': 2, 'date': 2, 'racing': 2,
    'download': 2, 'stream': 2, 'accountant': 2, 'loan': 2,
    'click': 2, 'link': 2, 'win': 2, 'men': 2, 'party': 2,

    # Elevated risk (score 1) — legitimate but frequently abused
    'info': 1, 'biz': 1, 'online': 1, 'site': 1, 'tech': 1,
    'store': 1, 'club': 1, 'live': 1, 'space': 1, 'fun': 1,

    # Trusted (score 0, default) — .com, .org, .net, .gov, .edu etc.
}

# Helper functions
def deep_decode(text: str) -> str:
    """
    Recursively URL-decodes until the string stops changing.
    Defeats multi-layer percent-encoding obfuscation like %2561 → %61 → a.
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
    Shannon entropy of a string.
    High value → highly random characters → typical of generated/obfuscated domains.
    """
    if not text:
        return 0.0
    length  = len(text)
    entropy = 0.0
    for count in Counter(text).values():
        p        = count / length
        entropy -= p * math.log2(p)
    return entropy

def brand_lookalike_score(domain: str) -> int:
    """
    Returns the minimum Levenshtein edit distance between the domain's
    registered name and every brand in BRAND_TARGETS.
    Low score (0-2) + domain not in whitelist = strong phishing signal.
    Catches: paypa1.com (dist=1), g00gle.com (dist=2), etc.
    """
    if not domain:
        return 99
    return min(
        fuzz_distance.Levenshtein.distance(domain.lower(), brand)
        for brand in BRAND_TARGETS
    )

# Main Feature Extraction
def extract_features(url: str) -> dict | None:
    """
    Extracts a fixed set of numerical features from a URL string.
    Returns a feature dict, or None if the URL is empty / unparseable.
    All 22 features are fast lexical/structural operations.
    No network calls are made here.
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

    # 2. Entropy (randomness)
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
    #Legitimate sites use domain names; phishing pages often use raw IPs.
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    features['has_ip_in_domain'] = 1 if re.search(ip_pattern, parsed.netloc) else 0

    # 6. Keyword-based signals
    decoded_url = deep_decode(url)
    suspicious_keywords = [
        'login', 'secure', 'account', 'update', 'banking',
        'confirm', 'verify', 'password', 'ebay', 'paypal',
        'signin', 'upi', 'wallet', 'auth', 'credential',
    ]
    features['suspicious_keyword_count'] = sum(
        1 for kw in suspicious_keywords if kw in decoded_url
    )

    # 7. Subdomain depth
    #    paypal.account-update.verify.com has depth 2 — highly suspicious.
    #    Legitimate sites rarely exceed depth 1.
    subdomain = extracted.subdomain or ''
    features['subdomain_depth'] = len(subdomain.split('.')) if subdomain else 0

    # 8. TLD risk score
    #    .tk / .ml / .ga = free TLDs heavily used for phishing (score 2)
    #    .info / .biz / .online = elevated risk (score 1)
    #    Everything else = 0
    tld = extracted.suffix.split('.')[-1].lower() if extracted.suffix else ''
    features['tld_risk_score'] = TLD_RISK_MAP.get(tld, 0)

    # 9. Brand lookalike score
    #    Min edit distance to top phishing target brands.
    #    paypa1.com → distance 1 from 'paypal' = very suspicious.
    features['brand_lookalike_score'] = brand_lookalike_score(extracted.domain)

    # 10. NEW: Digit ratio in domain
    #     g00gle.com, paypa1.com — digits substituted for letters.
    domain_str = extracted.domain or ''
    digit_count = sum(1 for c in domain_str if c.isdigit())
    features['digit_ratio_in_domain'] = (
        digit_count / len(domain_str) if domain_str else 0.0
    )

    # 11. NEW: Punycode / homograph detection
    #     аpple.com (Cyrillic а) encodes to xn--pple-43d.com
    features['has_punycode'] = 1 if 'xn--' in parsed.netloc.lower() else 0

    # 12. NEW: Path depth
    #     /verify/account/login/update/confirm — deep paths are suspicious.
    path_parts = [p for p in parsed.path.split('/') if p]
    features['path_depth'] = len(path_parts)

    return features
