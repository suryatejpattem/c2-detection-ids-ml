import pandas as pd
from io import StringIO

def read_zeek(path):
    """Read a Zeek .log file into a pandas DataFrame."""
    fields = None
    data_lines = []

    with open(path) as f:
        for line in f:
            if line.startswith('#'):
                if line.startswith('#fields'):
                    fields = line.rstrip('\n').split('\t')[1:]
                continue          # skip ALL header/comment lines
            data_lines.append(line)

    if fields is None:
        raise ValueError(f"No #fields line found in {path}")

    if not data_lines:
        return pd.DataFrame(columns=fields)

    df = pd.read_csv(
        StringIO(''.join(data_lines)),
        sep='\t',
        names=fields,
        na_values=['-', '(empty)'],
    )
    return df
