"""bsimscore.py: score BsimTool query rows (best match per function) against a hand file, by similarity bucket.
Only functions with a decider-free hand name count (comment without libmatch / rules:), so it is a blind test.
Also counts how many good matches libmatch did not already name.

    py -3.13 -I bsimscore.py <query.tsv> <hand.txt> [libmatch out.txt]
"""
import collections, re, sys

q, hand = sys.argv[1], sys.argv[2]
lm = set()
if len(sys.argv) > 3:
    lm = {int(l.split()[0], 16) for l in open(sys.argv[3], encoding='utf-8') if l.startswith('0x')}
truth = {}
for l in open(hand, encoding='utf-8'):
    f = l.split(None, 4)
    if len(f) >= 3 and not ('libmatch' in l or 'rules:' in l): truth[int(f[0], 16)] = f[2]
best = {}
for l in open(q, encoding='utf-8'):
    f = l.split()
    if len(f) < 7: continue
    a, sim, sig = int(f[0], 16), float(f[5]), float(f[6])
    if a not in best or sim > best[a][1]: best[a] = (f[3], sim, sig, f[2])
words = lambda n: {w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+', re.sub(r'_\d+$', '', n))}
pre = lambda n: n.split('_')[0].lower()
st = collections.defaultdict(lambda: [0, 0, 0.0, 0])
for a, (m, sim, sig, exe) in best.items():
    if a not in truth or m.startswith('FUN_'): continue
    b = '%.1f' % min(int(sim * 10) / 10, 0.9)
    t = truth[a]
    s = st[b]; s[0] += 1; s[1] += pre(t) == pre(m)
    s[2] += len(words(t) & words(m)) / max(len(words(t) | words(m)), 1); s[3] += a not in lm
print('rows %d, functions with a match %d, blind-truth functions %d' % (sum(1 for _ in open(q)), len(best), len(truth)))
for b in sorted(st, reverse=True):
    n, p, ov, new = st[b]
    print('sim >= %s  n=%4d  same prefix %4d (%.0f%%)  overlap %.2f  not in libmatch %d' % (b, n, p, 100 * p / n, ov / n, new))
