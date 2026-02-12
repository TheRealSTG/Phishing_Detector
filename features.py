# Regular Expression module used for pattern matching
import re
# Used to break down the URLs into its constituent components, like its scheme, netloc, path
from urllib.parse import urlparse

# Inputs URL string 
def extract_features(url):
    # Initialises the empty dictionary
    features = {}

    # Handle empty or malformed URLs
    ## Ensures that the URL exists and is a string
    if not url or not isinstance(url, str):
        return None
    
    # Parses the URL, returns None if the parsing fails due to a malformed URL.
    try:
        parsed_url = urlparse(url)
    except:
        return None
    
    # Structure and Length Features
    ## Calculates the total URL Length
    features['url_length'] = len(url)
    ## Calculates the domain name length
    features['hostname_length'] = len(parsed_url.netloc)
    ## Calculates the path length 
    ### Sometimes, longer URLs are used in phishing.
    features['path_length'] = len(parsed_url.path)

    # Special character counting
    ## Phishers often use these to confuzzle users
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['at_count'] = url.count('@')
    features['question_count'] = url.count('?')
    features['percent_count'] = url.count('%')

    # Protocol and Port Checking
    ## Sets the flag to 1 if HTTPS is used. (this is more secure)
    ## Sets the flag to 0 if HTTPS is not used. (less secure)
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0

    # Check for weird ports
    ## Anything except 80 for HTTP or 443 for HTTPS.
    ## Non-standard ports are sus.
    try:
        port = parsed_url.port
        if port and port not in [80, 443]:
            features['is_non_std_port'] = 1
        else:
            features['is_non_std_port'] = 0
    except:
        features['is_non_std_port'] = 0 

    # Detection of IP Adresses
    ## Legit sites usually have domain names.
    ## Malware often live on raw IP addresses.
    ## Uses regex to check if the domain is a raw IP address instead of a domain name.
    ## Sets the flag to 1 if found.
    ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
    if re.search(ip_pattern, parsed_url.netloc):
        features['has_ip_in_domain'] = 1
    else:
        features['has_ip_in_domain'] = 0
    
    # Suspicious Keyword Detection
    ## Defines keywords that are commonly found in phisihing URLs.
    ## Loops through each keyword and counts how many times they appear in the URL
    ## This is case-insensitive.
    suspicious_keywords = [
        'login', 'secure', 'account', 'update', 'banking', 'confirm', 'verify', 'password',
        'ebay', 'paypal', 'signin', 'upi'
    ]

    match_count = 0
    for word in suspicious_keywords:
        if word in url.lower():
            match_count += 1
    features['suspicious_keyword_count'] = match_count

    return features