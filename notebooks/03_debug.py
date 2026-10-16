import pandas as pd

df = pd.read_csv('data/phishing_site_urls.csv')
good = df[df['Label'] == 'good']
bad = df[df['Label'] == 'bad']

print("Total GOOD:", len(good))
print("Total BAD:", len(bad))
print()

# Sample 10 good URLs
print("=" * 60)
print("SAMPLE 10 GOOD URLs:")
print("=" * 60)
print(good['URL'].sample(10, random_state=1).to_string(index=False))
print()

# Sample 10 bad URLs
print("=" * 60)
print("SAMPLE 10 BAD URLs:")
print("=" * 60)
print(bad['URL'].sample(10, random_state=1).to_string(index=False))
print()

# Check if simple google.com is in dataset
print("=" * 60)
print("CHECK: Is 'google.com' in GOOD?")
print("=" * 60)
matches = good[good['URL'] == 'google.com']
print(f"Exact match 'google.com': {len(matches)}")
matches = good[good['URL'].str.contains('google', case=False, na=False)]
print(f"Contains 'google' in GOOD: {len(matches)}")
matches = bad[bad['URL'].str.contains('google', case=False, na=False)]
print(f"Contains 'google' in BAD: {len(matches)}")