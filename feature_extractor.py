import re
from urllib.parse import urlparse

def extract_features(url):
    """Extract features from a URL for phishing detection."""
    features = {}
    
    try:
        url = str(url)
    except:
        url = ""
    
    # Parse URL with error handling
    try:
        if not url.startswith(('http://', 'https://')):
            url_parsed = urlparse('http://' + url)
        else:
            url_parsed = urlparse(url)
    except Exception:
        url_parsed = urlparse('http://invalid.com')
    
    # ============ BASIC LENGTH FEATURES ============
    features['url_length'] = len(url)
    features['hostname_length'] = len(url_parsed.netloc)
    features['path_length'] = len(url_parsed.path)
    
    # ============ DOT / HYPHEN / DIGIT FEATURES ============
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special_chars'] = len(re.findall(r'[?=&%#@!$]', url))
    
    # ============ SECURITY FEATURES ============
    features['has_https'] = 1 if url.startswith('https://') else 0
    features['has_ip_address'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_parsed.netloc) else 0
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in url_parsed.path else 0
    
    # ============ DOMAIN FEATURES ============
    hostname = url_parsed.netloc.lower()
    parts = hostname.split('.')
    features['num_subdomains'] = max(0, len(parts) - 2)
    
    # Suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', 
                       '.work', '.click', '.link', '.loan', '.download', 
                       '.stream', '.racing', '.win', '.bid', '.review']
    features['has_suspicious_tld'] = 1 if any(url.endswith(tld) or (tld + '/') in url for tld in suspicious_tlds) else 0
    
    # ============ IMPROVED BRAND DETECTION ============
    # Only flag as brand impersonation if:
    # - brand appears in subdomain or path
    # - AND the main domain is NOT that brand
    brands = ['paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft',
              'netflix', 'wellsfargo', 'chase', 'citibank', 'hsbc',
              'ebay', 'instagram', 'whatsapp', 'linkedin', 'dropbox', 'adobe',
              'dhl', 'fedex', 'usps', 'steam', 'binance', 'coinbase']
    
    main_domain = parts[-2] if len(parts) >= 2 else ''
    brand_present = any(brand in hostname for brand in brands)
    main_domain_is_brand = main_domain in brands
    
    # Only suspicious if brand is present but NOT the main domain
    features['has_brand'] = 1 if (brand_present and not main_domain_is_brand) else 0
    features['brand_in_path'] = 1 if any(brand in url_parsed.path.lower() for brand in brands) else 0
    
    # ============ SUSPICIOUS KEYWORDS ============
    keywords = ['login', 'signin', 'verify', 'account', 'update', 'secure',
                'confirm', 'banking', 'password', 'credential', 'alert',
                'suspended', 'unlock', 'recover', 'validate']
    
    features['has_suspicious_keyword'] = 1 if any(kw in url.lower() for kw in keywords) else 0
    features['suspicious_keyword_count'] = sum(1 for kw in keywords if kw in url.lower())
    
    # ============ ENCODED CHARACTERS ============
    features['has_hex_encoding'] = 1 if '%' in url else 0
    features['hex_count'] = url.count('%')
    
    # ============ TLD LENGTH ============
    tld = '.' + parts[-1] if len(parts) > 1 else ''
    features['tld_length'] = len(tld)

    # ============ SHORT / ROOT URL FEATURES ============
    parsed_hostname = (url_parsed.hostname or '').lower()
    features['is_short_url'] = 1 if len(url) < 30 else 0
    features['has_www'] = 1 if parsed_hostname.startswith('www.') else 0
    features['is_root_domain'] = 1 if url_parsed.path in ('', '/') else 0
    features['is_https_only'] = 1 if url.startswith('https://') and len(url) < 40 else 0

    return features


if __name__ == "__main__":
    test_urls = [
        'https://www.google.com',
        'https://github.com',
        'https://www.paypal.com',
        'http://paypal-verify.xyz/login/account/confirm',
        'http://amazon-security-update.tk/verify-account',
        'http://192.168.1.1/admin/login.php',
    ]
    
    print("=" * 80)
    print("🔧 FEATURE EXTRACTION TEST")
    print("=" * 80)
    
    for url in test_urls:
        print(f"\n🔗 URL: {url}")
        features = extract_features(url)
        print(f"   has_brand              = {features['has_brand']}")
        print(f"   has_suspicious_tld     = {features['has_suspicious_tld']}")
        print(f"   has_https              = {features['has_https']}")
        print(f"   suspicious_keywords    = {features['suspicious_keyword_count']}")