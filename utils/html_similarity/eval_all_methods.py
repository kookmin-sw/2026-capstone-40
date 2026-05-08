import pandas as pd
import numpy as np
from itertools import combinations

path = r'output\result_html_similarity_260504_1106\results.xlsx'

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

METHODS = ['dom_sequence', 'dom_content', 'subtree_hash', 'subtree_hash_multi',
           'pq_gram', 'path_signature', 'shape_content']

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

def build_pairs(df):
    sites = list(df.index)
    pairs = []
    for a, b in combinations(sites, 2):
        da, db = get_domain(a), get_domain(b)
        ga, gb = GROUPS.get(da), GROUPS.get(db)
        same = int(ga == gb and ga not in (None, 'neg'))
        sim = df.loc[a, b]
        pairs.append((a, b, sim, same))
    return pd.DataFrame(pairs, columns=['a', 'b', 'sim', 'label'])

def best_threshold(pair_df):
    best_f1, best_t, best_row = 0, 0, None
    for t in np.arange(0.01, 1.00, 0.01):
        pred = (pair_df['sim'] >= t).astype(int)
        y = pair_df['label']
        tp = int(((y==1)&(pred==1)).sum())
        tn = int(((y==0)&(pred==0)).sum())
        fp = int(((y==0)&(pred==1)).sum())
        fn = int(((y==1)&(pred==0)).sum())
        acc  = (tp+tn)/(tp+tn+fp+fn)
        prec = tp/(tp+fp) if tp+fp>0 else 0
        rec  = tp/(tp+fn) if tp+fn>0 else 0
        f1   = 2*prec*rec/(prec+rec) if prec+rec>0 else 0
        if f1 > best_f1:
            best_f1, best_t = f1, round(t, 2)
            best_row = (round(t,2), tp, tn, fp, fn, acc, prec, rec, f1)
    return best_row

# ── 방법별 최적 threshold 요약 ─────────────────────────────────────────
print("=" * 82)
print(f"{'Method':<22} {'Threshold':>9} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
print("=" * 82)

summaries = {}
for method in METHODS:
    df = pd.read_excel(path, sheet_name=method, index_col=0)
    pair_df = build_pairs(df)
    row = best_threshold(pair_df)
    summaries[method] = (pair_df, row)
    t, tp, tn, fp, fn, acc, prec, rec, f1 = row
    print(f"  {method:<20} {t:>9.2f} {tp:>4} {tn:>4} {fp:>4} {fn:>4} {acc:>7.4f} {prec:>7.4f} {rec:>7.4f} {f1:>7.4f}")

print("=" * 82)

# ── 방법별 상세 threshold 테이블 ───────────────────────────────────────
for method in METHODS:
    pair_df, best_row = summaries[method]
    best_t = best_row[0]
    print(f"\n{'─'*68}")
    print(f"[{method}]  최적 threshold={best_t}  |  동일도메인 쌍 유사도:")
    pos = pair_df[pair_df['label']==1][['a','b','sim']].sort_values('sim', ascending=False)
    for _, r in pos.iterrows():
        a_short = r['a'].replace('.html','').replace('_archive','')
        b_short = r['b'].replace('.html','').replace('_archive','')
        print(f"    {a_short:<38}  vs  {b_short:<38}  {r['sim']:.4f}")

    print(f"\n  {'threshold':>10} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Acc':>7} {'Prec':>7} {'Rec':>7} {'F1':>7}")
    seen_f1 = set()
    for t in np.arange(0.01, 1.00, 0.01):
        pred = (pair_df['sim'] >= t).astype(int)
        y = pair_df['label']
        tp = int(((y==1)&(pred==1)).sum())
        tn = int(((y==0)&(pred==0)).sum())
        fp = int(((y==0)&(pred==1)).sum())
        fn = int(((y==1)&(pred==0)).sum())
        acc  = (tp+tn)/(tp+tn+fp+fn)
        prec = tp/(tp+fp) if tp+fp>0 else 0
        rec  = tp/(tp+fn) if tp+fn>0 else 0
        f1   = 2*prec*rec/(prec+rec) if prec+rec>0 else 0
        key  = (tp, tn, fp, fn)
        if key in seen_f1:
            continue
        seen_f1.add(key)
        mark = " <- 최적" if round(t,2) == best_t else ""
        print(f"    {t:>8.2f}   {tp:>3}  {tn:>3}  {fp:>3}  {fn:>3}  {acc:>6.4f}  {prec:>6.4f}  {rec:>6.4f}  {f1:>6.4f}{mark}")
