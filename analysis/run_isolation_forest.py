import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ['n_events', 'median_gap', 'mad_gap', 'rcv', 'median_bytes']

df = pd.read_csv('features_conn.csv')
print(f'rows loaded: {len(df)}')

# median_bytes may be missing for some rows; fill with 0 so they are not dropped
df['median_bytes'] = df['median_bytes'].fillna(0)
df['rcv'] = df['rcv'].fillna(0)

before = len(df)
df = df.dropna(subset=FEATURES).reset_index(drop=True)
print(f'rows after dropping incomplete: {len(df)} (removed {before - len(df)})')
print()

# log-compress the wide-ranging features, then standardise all of them
X = df[FEATURES].copy()
for c in ['n_events', 'median_gap', 'mad_gap', 'median_bytes']:
    X[c] = np.log1p(X[c])

X_scaled = StandardScaler().fit_transform(X)

for contamination in [0.05, 0.10, 0.20]:
    model = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=200,
    )
    pred = model.fit_predict(X_scaled)      # -1 = anomaly, 1 = normal
    score = model.score_samples(X_scaled)   # lower = more anomalous

    col = f'flag_{contamination}'
    df[col] = (pred == -1)
    df['score'] = score

    n = df[col].sum()
    print(f'=== contamination = {contamination} -> {n} flagged ===')
    flagged = df[df[col]].sort_values('score')
    print(flagged[['capture', 'dest', 'dest_port', 'label',
                   'n_events', 'median_gap', 'rcv']].to_string(index=False))
    print()

df.to_csv('conn_scored.csv', index=False)
print('WROTE conn_scored.csv')
