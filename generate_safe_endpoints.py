"""
Generate a large list of safe/normal web endpoints.
Uses common patterns from popular APIs and websites.
"""
import pandas as pd
import random
from pathlib import Path

# Set seed for reproducibility
random.seed(42)

# Popular safe domains
safe_domains = [
    'api.github.com', 'api.twitter.com', 'api.facebook.com', 'api.google.com',
    'api.microsoft.com', 'api.amazon.com', 'api.stripe.com', 'api.twilio.com',
    'api.slack.com', 'api.dropbox.com', 'api.spotify.com', 'api.reddit.com',
    'api.linkedin.com', 'api.instagram.com', 'api.paypal.com', 'api.shopify.com',
    'api.zoom.us', 'api.atlassian.com', 'api.salesforce.com', 'api.okta.com',
    'www.google.com', 'www.github.com', 'www.stackoverflow.com', 'www.wikipedia.org',
    'www.youtube.com', 'www.facebook.com', 'www.twitter.com', 'www.linkedin.com',
    'www.reddit.com', 'www.amazon.com', 'www.microsoft.com', 'www.apple.com',
    'www.netflix.com', 'www.spotify.com', 'www.medium.com', 'www.quora.com',
    'www.bbc.com', 'www.cnn.com', 'www.nytimes.com', 'www.theguardian.com',
    'secure.example.com', 'api.example.com', 'www.example.com', 'app.example.com',
    'dashboard.example.com', 'admin.example.com', 'portal.example.com'
]

# Common safe API endpoints
api_paths = [
    '/api/v1/users', '/api/v1/data', '/api/v1/status', '/api/v1/health',
    '/api/v2/users', '/api/v2/posts', '/api/v2/comments', '/api/v2/likes',
    '/api/users', '/api/posts', '/api/comments', '/api/products',
    '/api/orders', '/api/customers', '/api/inventory', '/api/settings',
    '/users', '/posts', '/comments', '/products', '/orders', '/dashboard',
    '/profile', '/settings', '/account', '/login', '/register', '/logout',
    '/home', '/about', '/contact', '/help', '/support', '/docs', '/api-docs',
    '/health', '/status', '/ping', '/metrics', '/info', '/version'
]

# Common query parameters (safe)
safe_params = [
    '', 'page=1', 'limit=10', 'offset=0', 'sort=name', 'order=asc',
    'filter=active', 'status=published', 'category=tech', 'type=article',
    'format=json', 'lang=en', 'locale=en_US', 'timezone=UTC'
]

# HTTP methods (safe usage)
methods = ['GET', 'GET', 'GET', 'GET', 'POST']  # Mostly GET, some POST

# Headers (safe)
safe_headers = [
    'User-Agent: Mozilla/5.0',
    'User-Agent: Chrome',
    'User-Agent: Firefox',
    'User-Agent: Safari',
    'Accept: application/json',
    'Content-Type: application/json',
    'Authorization: Bearer token',
    'Accept-Language: en-US'
]

safe_endpoints = []

print("Generating safe endpoints...")

# Generate 1000+ safe endpoints
for i in range(1200):  # Generate extra to ensure we have 1000+ unique
    domain = random.choice(safe_domains)
    path = random.choice(api_paths)
    
    # Sometimes add ID or slug
    if random.random() > 0.6:
        if '/users' in path or '/posts' in path:
            path = f"{path}/{random.randint(1, 1000)}"
        elif '/api' in path:
            path = f"{path}/{random.randint(1, 100)}"
    
    # Add query parameters sometimes
    query = ''
    if random.random() > 0.5:
        query = random.choice(safe_params)
    
    # Build URL
    url = f"https://{domain}{path}"
    if query:
        url = f"{url}?{query}"
    
    method = random.choice(methods)
    headers = random.choice(safe_headers)
    
    safe_endpoints.append({
        'request_url': url,
        'http_method': method,
        'query': query,
        'request_headers': headers,
        'is_attack': 0
    })

# Create DataFrame
df = pd.DataFrame(safe_endpoints)

# Remove duplicates
df = df.drop_duplicates(subset=['request_url'], keep='first')

print(f"\nGenerated {len(df)} unique safe endpoints")

# Save
output_path = Path('data/raw/safe_endpoints_generated.csv')
output_path.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(output_path, index=False)

print(f"Saved to {output_path}")
print(f"\nSample endpoints:")
print(df[['request_url', 'http_method']].head(10).to_string(index=False))


