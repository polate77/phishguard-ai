import pandas as pd

# Load dataset
df = pd.read_csv('data/phishing_site_urls.csv')

# Show basic info
print("=" * 60)
print("📊 DATASET OVERVIEW")
print("=" * 60)
print(f"Total URLs: {len(df):,}")
print(f"Columns: {list(df.columns)}")
print()

# Show first few rows
print("=" * 60)
print("📄 FIRST 5 ROWS")
print("=" * 60)
print(df.head())
print()

# Check label distribution
print("=" * 60)
print("🏷️ LABEL DISTRIBUTION")
print("=" * 60)
print(df['Label'].value_counts())
print()

# Check for missing values
print("=" * 60)
print("❓ MISSING VALUES")
print("=" * 60)
print(df.isnull().sum())
print()

# Sample URLs from each class
print("=" * 60)
print("🔗 SAMPLE URLS")
print("=" * 60)
print("Good URLs:")
print(df[df['Label'] == 'good']['URL'].head(3).to_string(index=False))
print()
print("Bad URLs (phishing):")
print(df[df['Label'] == 'bad']['URL'].head(3).to_string(index=False))