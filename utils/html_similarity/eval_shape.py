import pandas as pd
import numpy as np
from itertools import combinations

path = r'output\result_html_similarity_260504_1106\results.xlsx'
df = pd.read_excel(path, sheet_name='shape_content', index_col=0)

GROUPS = {
    'linkkf.live':    'linkkf',
    'linkkf.tv':      'linkkf',
    'ohli24.net':     'ohli',
    'ani.ohli24.com': 'ohli',
    'ohli365.org':    'ohli',
    'anilife.app':    'anilife',
    'anilife.live':   'anilife',
    'newtoki469.com': 'newtoki',
    'wfwf449.com':    'wfwf',
    'laftel.net':     'neg',
    'naver.com':      'neg',
    'sbs.co.kr':      'neg',
    'youtube.com':    'neg',
}

def get_domain(fname):
    stem = fname.replace('.html', '')
    parts = stem.split('_')
    domain_parts = []
    for p in parts:
        if p.isdigit() and len(p) >= 6:
            break
        if p == 'archive':
            break
        domain_parts.append(p)
    return '_'.join(domain_parts)

sites = list(df.index)
pairs = []
for a, b in combinations(sites, 2):
    da = get_domain(a)
    db = get_domain(b)
    ga = GROUPS.get(da)
    gb = GROUPS.get(db)
    same = int(ga == gb and ga not in (None, 'neg'))
    sim = df.loc[a, b]
    pairs.append((a, b, sim, same))

pair_df = pd.DataFrame(pairs, columns=['a', 'b', 'sim', 'label'])
print(f"전체 쌍: {len(pair_df)}  |  동일 도메인(+): {pair_df['label'].sum()}  |  다른 도메인(-): {(pair_df['label']==0).sum()}")

print("\n[동일 도메인 쌍 유사도]")
pos = pair_df[pair_df['label'] == 1][['a', 'b', 'sim']].sort_values('sim', ascending=False)
print(pos.to_string(index=False))

print("\n[메트릭 by threshold]")
print(f"{'threshold':>10} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
print("-" * 68)

best_f1, best_t = 0, 0
results = []
for t in np.arange(0.01, 0.70, 0.01):
    pred = (pair_df['sim'] >= t).astype(int)
    y = pair_df['label']
    tp = int(((y == 1) & (pred == 1)).sum())
    tn = int(((y == 0) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    fn = int(((y == 1) & (pred == 0)).sum())
    acc  = (tp + tn) / (tp + tn + fp + fn)
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    rec  = tp / (tp + fn) if tp + fn > 0 else 0
    f1   = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
    results.append((round(t, 2), tp, tn, fp, fn, acc, prec, rec, f1))
    if f1 > best_f1:
        best_f1, best_t = f1, round(t, 2)

for r in results:
    t, tp, tn, fp, fn, acc, prec, rec, f1 = r
    mark = " <- 최적" if t == best_t else ""
    print(f"  {t:>6.2f}   {tp:>3}  {tn:>3}  {fp:>3}  {fn:>3}  {acc:>6.4f}  {prec:>6.4f}  {rec:>6.4f}  {f1:>6.4f}{mark}")

# 최적 threshold로 분류
print(f"\n{'='*60}")
print(f"최적 Threshold: {best_t}")
r = [x for x in results if x[0] == best_t][0]
t, tp, tn, fp, fn, acc, prec, rec, f1 = r
print(f"  TP={tp}  TN={tn}  FP={fp}  FN={fn}")
print(f"  Accuracy : {acc:.4f}")
print(f"  Precision: {prec:.4f}")
print(f"  Recall   : {rec:.4f}")
print(f"  F1 Score : {f1:.4f}")
print(f"{'='*60}")

# threshold 기준 연결 그래프 → 연결된 컴포넌트로 분류
print(f"\n[threshold={best_t} 기준 사이트 분류]")
from collections import defaultdict

edges = pair_df[pair_df['sim'] >= best_t][['a', 'b', 'sim']]
print(f"\n연결된 쌍 ({len(edges)}개):")
for _, row in edges.iterrows():
    print(f"  {row['a']}  <->  {row['b']}  (sim={row['sim']:.4f})")

# Union-Find
parent = {s: s for s in sites}
def find(x):
    while parent[x] != x:
        parent[x] = parent[parent[x]]
        x = parent[x]
    return x
def union(x, y):
    parent[find(x)] = find(y)

for _, row in edges.iterrows():
    union(row['a'], row['b'])

groups = defaultdict(list)
for s in sites:
    groups[find(s)].append(s)

print(f"\n[분류 결과 - {len(groups)}개 그룹]")
for i, (_, members) in enumerate(sorted(groups.items(), key=lambda x: -len(x[1])), 1):
    label = get_domain(members[0])
    g = GROUPS.get(label, '?')
    print(f"  Group {i} ({len(members)}개 사이트):")
    for m in sorted(members):
        dom = get_domain(m)
        grp = GROUPS.get(dom, '?')
        print(f"    - {m}  [{grp}]")
