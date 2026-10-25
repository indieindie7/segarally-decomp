"""structclust.py: merge StructAccess.java rows into struct candidates (access-pattern clustering).
Nodes are (function, base) pairs; a P row (pointer passed unchanged as call argument k) joins (caller, base) with
(callee, p<k>); global bases join on the global they point at. Each cluster = one struct with a field table
(offset, sizes, reads, writes, functions using it).

A u<reg> base (pointer kept in callee-saved r8..r14) is joined from caller to callee over the funcinfo call edges.

    py -3.13 -I structclust.py <structacc.tsv> <hand.txt> <out.txt> [min functions 3] [funcinfo.tsv]
"""
import collections, sys

acc, hand, out = sys.argv[1:4]
minf = int(sys.argv[4]) if len(sys.argv) > 4 else 3
names = {}
for l in open(hand, encoding='utf-8'):
    f = l.split(None, 3)
    if len(f) >= 3 and f[0].startswith('0x'): names[int(f[0], 16)] = f[2]

par = {}
def find(x):
    while par.setdefault(x, x) != x:
        par[x] = par[par[x]]; x = par[x]
    return x
why = []
def join(a, b, how=''):
    if find(a) != find(b): why.append((a, b, how))
    par[find(a)] = find(b)

def gnode(base):
    # g<slot>:<value>: a literal-pool slot holding a RAM address names that global; else the slot is the variable
    slot, val = base[1:].split(':')
    v = int(val, 16) if val != '-' else 0
    return ('G', '%08x' % v) if 0x06000000 <= v < 0x06100000 or 0x00200000 <= v < 0x00300000 else ('G', slot)

hub = collections.Counter()
for l in open(acc, encoding='utf-8'):
    t = l.split()
    if t and t[0] == 'P' and int(t[5]) == 0: hub[(int(t[3], 16), t[4])] += 1
HUB = 8                                  # a callee argument fed from more places is a generic helper: do not merge

fields = collections.defaultdict(lambda: collections.defaultdict(lambda: [set(), 0, 0, set()]))
rows, edges = [], []
for l in open(acc, encoding='utf-8'):
    t = l.split()
    if not t: continue
    fn = int(t[1], 16)
    node = gnode(t[2]) if t[2][0] == 'g' else (fn, t[2])
    if t[0] == 'A':
        rows.append((node, int(t[3]), int(t[4]), t[5], fn)); find(node)
    elif t[0] == 'P' and int(t[5]) == 0 and hub[(int(t[3], 16), t[4])] <= HUB:
        edges.append(((int(t[3], 16), 'p' + t[4]), node))

# a callee parameter used only as a small vector (<= 4 fields inside 0x10 bytes) or by a math_ helper is generic
# (vec3 / vertex / matrix helpers): joining through it glues unrelated structs together
offs = collections.defaultdict(set)
for node, off, *_ in rows: offs[node].add(off)
def generic(n):
    o = offs.get(n)
    return names.get(n[0], '').startswith('math_') or (o and len(o) <= 4 and max(o) - min(o) <= 0xc)
for callee, node in edges:
    if not generic(callee): join(callee, node, 'P')

if len(sys.argv) > 5:                    # callee-saved register pointers flow unchanged into callees
    have = {n for n, *_ in rows if n[1][0] == "u"}
    wrote = {(int(t[1], 16), t[2]) for t in (l.split() for l in open(acc, encoding="utf-8")) if t and t[0] == "W"}
    cand, cur = [], None
    for l in open(sys.argv[5], encoding='utf-8', errors='replace'):
        t = l.rstrip(chr(10)).split(' ', 1)
        if t[0] == 'F': cur = int(t[1].split()[0], 16)
        elif t[0] == 'C' and cur is not None:
            c = int(t[1], 16)
            for r in ('ur8', 'ur9', 'ur10', 'ur11', 'ur12', 'ur13', 'ur14'):
                if (cur, r) in have and (c, r) in have and (cur, r) not in wrote: cand.append(((c, r), (cur, r)))
    # same guards as the P joins: a register fed from more than RHUB callers, or a generic helper, is not one struct
    RHUB = 2
    feed = collections.Counter(c for c, _ in set(cand))
    for c, node in cand:
        if feed[c] <= RHUB and not names.get(c[0], '').startswith('math_'): join(c, node, 'R')

for node, off, sz, rw, fn in rows:
    if off < 0 or off > 0x2000: continue
    f = fields[find(node)][off]
    f[0].add(sz); f[1] += rw == 'R'; f[2] += rw == 'W'; f[3].add(fn)

nm = lambda a: names.get(a, 'FUN_%08x' % a)
cl = []
for root, fs in fields.items():
    funcs = set().union(*(f[3] for f in fs.values()))
    if len(funcs) < minf or len(fs) < 2: continue
    cl.append((len(funcs), root, fs, funcs))
cl.sort(key=lambda c: -c[0])
with open(out, 'w', encoding='utf-8') as w:
    for i, (n, root, fs, funcs) in enumerate(cl):
        top = max(fs)
        glob = root[1] if root[0] == 'G' else ''
        w.write('#### S%03d %d functions, %d fields, size >= 0x%x%s\n' % (i, n, len(fs), top + max(fs[top][0]),
                ', global 0x' + glob if glob else ''))
        w.write('users: %s\n' % ' '.join(sorted(nm(a) for a in funcs)[:40]))
        for off in sorted(fs):
            sz, r, wr, ff = fs[off]
            w.write('  +0x%03x %s R%d W%d  %s\n' % (off, '/'.join(str(s) for s in sorted(sz)), r, wr,
                    ' '.join(sorted(nm(a) for a in ff)[:6])))
if cl:   # STRUCTWHY=1: show the joins that built the biggest struct
    import os
    if os.environ.get('STRUCTWHY'):
        for a, b, how in why:
            if find(a) == cl[0][1]: print('join', how, nm(a[0]) if isinstance(a[0], int) else a, a[1], '<-', nm(b[0]) if isinstance(b[0], int) else b, b[1])
print('structs %d (>= %d functions), biggest %s' % (len(cl), minf, ', '.join('%d fn/%d fields' % (c[0], len(c[2])) for c in cl[:6])))
