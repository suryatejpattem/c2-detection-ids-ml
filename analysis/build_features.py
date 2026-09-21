import pandas as pd
import os
from zeek_reader import read_zeek

MIN_EVENTS = 10          # need >= 9 gaps for a meaningful statistic

# Known-malicious destinations, from ground-truth.md
MALICIOUS = {
    '45.131.214.85',      # C2 2026 NetSupport
    '38.146.28.242',      # C2 2025 NetSupport
    '79.141.165.202',     # 2025 StealC CnC (ET sids 2066280, 2066559)
    '45.61.150.28',       # 2025 payload download
    '172.86.90.13',       # 2025 early stage
    '209.59.180.92',      # 2025 early stage
    '135.148.121.246',    # 2022 Emotet C2 (from 172.16.0.149)
    '59.148.253.194',     # 2022 Emotet C2 (from 172.16.0.170)
    '141.98.10.79',       # 2024 STRRAT C2
}

# Traffic we generated ourselves - benign but automated
SYNTHETIC = {
    'detectportal.firefox.com',
    'www.msftconnecttest.com',
}


def describe_gaps(times):
    """Turn a series of timestamps into gap statistics."""
    g = times.sort_values().diff().dropna()      # SORT then diff
    if len(g) < MIN_EVENTS - 1:
        return None

    median = g.median()
    mad = (g - median).abs().median()
    mean = g.mean()
    std = g.std()

    return {
        'n_gaps': len(g),
        'median_gap': median,
        'mad_gap': mad,
        'rcv': mad / median if median > 0 else None,
        'mean_gap': mean,
        'std_gap': std,
        'cv': std / mean if mean > 0 else None,
        'min_gap': g.min(),
        'max_gap': g.max(),
    }


def build(logpath, capture, keycols, bytecol):
    """Build feature rows from one Zeek log."""
    if not os.path.exists(logpath):
        print(f'  [skip] {logpath} does not exist')
        return []

    df = read_zeek(logpath)
    if len(df) == 0:
        print(f'  [skip] {logpath} is empty')
        return []

    missing = [c for c in keycols + ['ts'] if c not in df.columns]
    if missing:
        print(f'  [skip] {logpath} missing columns: {missing}')
        return []

    df = df.dropna(subset=keycols + ['ts'])

    rows = []
    for key, group in df.groupby(keycols):
        if len(group) < MIN_EVENTS:
            continue
        s = describe_gaps(group['ts'])
        if s is None:
            continue

        dest = key[1]                                  # 2nd key element
        s['capture'] = capture
        s['source'] = key[0]
        s['dest'] = dest
        s['dest_port'] = key[2] if len(key) > 2 else None
        s['n_events'] = len(group)

        if bytecol and bytecol in group.columns:
            s['median_bytes'] = pd.to_numeric(
                group[bytecol], errors='coerce').median()
        else:
            s['median_bytes'] = None

        if dest in MALICIOUS:
            s['label'] = 'malicious'
        elif dest in SYNTHETIC:
            s['label'] = 'benign-synthetic'
        elif capture == 'benign':
            s['label'] = 'benign'
        else:
            s['label'] = 'unknown'

        rows.append(s)
    return rows


ZEEK = '/home/surya/project2/zeek'
captures = ['anchor', 'c2_2025', 'sunnystation', 'dirtyrat', 'benign']

# ---- Detector 1: http.log, grouped by (source, host) ----
print('=== DETECTOR 1 (http.log) ===')
d1 = []
for cap in captures:
    print(f'{cap}:')
    r = build(f'{ZEEK}/{cap}/http.log', cap,
              ['id.orig_h', 'host'], 'request_body_len')
    print(f'  {len(r)} groups')
    d1 += r

# ---- Detector 2: conn.log, grouped by (source, dest, port) ----
print()
print('=== DETECTOR 2 (conn.log) ===')
d2 = []
for cap in captures:
    print(f'{cap}:')
    r = build(f'{ZEEK}/{cap}/conn.log', cap,
              ['id.orig_h', 'id.resp_h', 'id.resp_p'], 'orig_bytes')
    print(f'  {len(r)} groups')
    d2 += r

cols = ['capture', 'source', 'dest', 'dest_port', 'label',
        'n_events', 'n_gaps',
        'median_gap', 'mad_gap', 'rcv',
        'mean_gap', 'std_gap', 'cv', 'min_gap', 'max_gap', 'median_bytes']

pd.DataFrame(d1)[cols].to_csv('features_http.csv', index=False)
pd.DataFrame(d2)[cols].to_csv('features_conn.csv', index=False)

print()
print(f'WROTE features_http.csv : {len(d1)} rows')
print(f'WROTE features_conn.csv : {len(d2)} rows')

print()
print('=== LABEL COUNTS ===')
print('HTTP:')
print(pd.DataFrame(d1)['label'].value_counts().to_string())
print()
print('CONN:')
print(pd.DataFrame(d2)['label'].value_counts().to_string())
