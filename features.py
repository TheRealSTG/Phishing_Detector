import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}

    # Handle empty or malformed URLs
    if not url or not isinstance(url, str):
        return None
    
    try:
        parsed_url = urlparse(url)
    except:
        return None
    
    # Structure and Length Features
    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc)
    features['path_length'] = len(parsed_url.path)

    # Special character counting
        ## Phishers often use these to confuzzle users
    features['dot_count'] = url.count('.')
    features['hyphen_count'] = url.count('-')
    features['at_count'] = url.count('@')
    features['question_count'] = url.count('?')
    features['percent_count'] = url.count('%')

    # Protocol and Port Checking
    features['is_https'] = 1 if parsed_url.scheme == 'https' else 0

    # Check for weird ports
        ## Anything except 30 or 443
    try:
        port = parsed_url.port
        if port and port not in [80, 443]:
            features['is_non_std_port'] = 1
        else:
            features['is_non_std_port'] = 0
    except:
        features['is_non_std_port'] = 0 