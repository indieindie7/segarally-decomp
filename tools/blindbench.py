"""blindbench.py: blind naming benchmark. Masks every hand name that the decider did not give (comment without
"libmatch"/"rules:"), picks a sample of caller/callee clusters, and writes naming slices in two context styles:
  A = current style: function + caller list + up to 3 caller bodies, address order
  B = callees first (post-order inside the sample) + an evidence block per function (strings, hardware blocks,
      known callee/caller names, constants), still with up to 2 caller bodies
Score the agents' answers with gemcmp.py <hand> <answers>.

    py -3.13 -I blindbench.py <ghidra dir> <prog> <decomp.c> <n sample> <slices per variant> <out dir> [seed]
"""
import collections, os, random, re, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rules import hw

g, prog, dump, nsample, nsl, out = sys.argv[1:7]
seed = int(sys.argv[7]) if len(sys.argv) > 7 else 1
nsample, nsl = int(nsample), int(nsl)
os.makedirs(out, exist_ok=True)

hand = {}
for l in open(os.path.join(g, 'hand_%s.txt' % prog), encoding='utf-8'):
    f = l.split(None, 4)
    if len(f) >= 3: hand[int(f[0], 16)] = (f[2], f[4].strip() if len(f) > 4 else '')
known = {a for a, (n, c) in hand.items() if 'libmatch' in c or 'rules:' in c}
masked = {n: 'FUN_%08x' % a for a, (n, c) in hand.items() if a not in known}
pat = re.compile(r'(?<![A-Za-z0-9])(' + '|'.join(re.escape(n) for n in sorted(masked, key=len, reverse=True))
                 + r')(?![A-Za-z0-9])(?!_\d{1,2}(?![0-9a-fA-F]))')
mask = lambda t: pat.sub(lambda m: masked[m.group(1)], t)

HDR = re.compile(r'^// ==== (\S+) @ ([0-9a-fA-F]+) size=(\d+)', re.M)
txt = open(os.path.join(g, dump), encoding='utf-8', errors='replace').read()
ms = list(HDR.finditer(txt))
body, size = {}, {}
for i, m in enumerate(ms):
    a = int(m.group(2), 16)
    b = txt[m.start():ms[i + 1].start() if i + 1 < len(ms) else len(txt)]
    b = re.sub(r'/\* Hand-named:.*?\*/\s*', '', b, flags=re.S)
    body[a], size[a] = mask(b), int(m.group(3))

callees, callers, strs, cur = collections.defaultdict(list), collections.defaultdict(set), collections.defaultdict(list), None
for l in open(os.path.join(g, 'funcinfo_%s.tsv' % prog), encoding='utf-8', errors='replace'):
    t = l.rstrip('\n').split(' ', 1)
    if t[0] == 'F': cur = int(t[1].split()[0], 16)
    elif t[0] == 'C' and cur is not None:
        c = int(t[1], 16); callees[cur].append(c); callers[c].add(cur)
    elif t[0] == 'S' and cur is not None and t[1] not in strs[cur]: strs[cur].append(t[1])
# literal-pool calls (SH-2): PTR_<name>_<addr> / PTR_FUN_<addr> in the dump
for a, b in body.items():
    for m in re.finditer(r'PTR_FUN_([0-9a-f]{8})', b):
        c = int(m.group(1), 16)
        if c in hand and c != a and c not in callees[a]: callees[a].append(c); callers[c].add(a)
    for n in re.findall(r'PTR_([A-Za-z]\w*?)_[0-9a-f]{8}', b):
        for c, (hn, _) in hand.items():
            if hn == n and c in known and c != a and c not in callees[a]: callees[a].append(c); callers[c].add(a)

nm = lambda a: hand[a][0] if a in known else 'FUN_%08x' % a
cand = sorted(a for a in hand if a not in known and a in body and size.get(a, 0) >= 24)
rnd = random.Random(seed)
sample, order = set(), []
while len(sample) < nsample:
    r = rnd.choice(cand)
    if r in sample: continue
    q, grp = [r], []
    while q and len(grp) < 8 and len(sample) + len(grp) < nsample:
        x = q.pop(0)
        if x in sample or x in grp or x not in body or x in known: continue
        grp.append(x); q.extend(callees[x])
    sample.update(grp)

def post(xs):
    seen, outl = set(), []
    def v(x, d=0):
        if x in seen: return
        seen.add(x)
        for c in callees[x]:
            if c in xs and d < 200: v(c, d + 1)
        outl.append(x)
    for x in sorted(xs): v(x)
    return outl

def trunc(t, n):
    s = t.splitlines()
    return '\n'.join(s[:n] + (['  ... (truncated, %d lines)' % len(s)] if len(s) > n else []))

def evidence(a):
    b = body[a]
    hb = sorted({h for v in re.findall(r'0x([0-9a-f]{7,8})', b) for h in [hw(int(v, 16))] if h})
    kc = sorted({nm(c) for c in callees[a] if c in known})
    uc = sorted({'FUN_%08x' % c for c in callees[a] if c not in known})
    kr = sorted({nm(c) for c in callers[a] if c in known})
    consts = sorted({v for v in re.findall(r'\b(0x[0-9a-f]{2,8}|\d{3,})\b', b)})[:12]
    e = ['evidence: size=%d bytes, %d callers, %d callees' % (size[a], len(callers[a]), len(set(callees[a])))]
    if hb: e.append('  hardware blocks touched: ' + ', '.join(hb))
    if strs[a]: e.append('  strings: ' + ' | '.join(strs[a][:6]))
    if kc: e.append('  named callees: ' + ', '.join(kc[:12]))
    if uc: e.append('  unnamed callees: ' + ', '.join(uc[:12]))
    if kr: e.append('  named callers: ' + ', '.join(kr[:8]))
    if consts: e.append('  constants: ' + ' '.join(consts))
    return '\n'.join(e)

def entry(a, style):
    t = '#### %s 0x%08x FUN_%08x\n' % (prog, a, a)
    if style == 'B': t += evidence(a) + '\n'
    t += trunc(body[a], 250) + '\n'
    cs = sorted(callers[a])
    t += '---- callers: %d (%s)\n' % (len(cs), ' '.join(nm(c) for c in cs[:12]))
    for c in cs[:3 if style == 'A' else 2]:
        if c in body: t += '---- caller %s\n%s\n' % (nm(c), trunc(body[c], 80))
    return t

for style, seq in (('A', sorted(sample)), ('B', post(sample))):
    items = [entry(a, style) for a in seq]
    per = (len(items) + nsl - 1) // nsl
    for k in range(nsl):
        open(os.path.join(out, '%s_%d.txt' % (style, k + 1)), 'w', encoding='utf-8').write('\n'.join(items[k * per:(k + 1) * per]))
open(os.path.join(out, 'sample.txt'), 'w').write('\n'.join('0x%08x %s' % (a, hand[a][0]) for a in sorted(sample)) + '\n')
leak = sum(1 for a in sample for n in [hand[a][0]] if any(re.search(r'(?<![A-Za-z0-9])%s(?![A-Za-z0-9])' % re.escape(n), open(os.path.join(out, f), encoding='utf-8').read()) for f in os.listdir(out) if f[0] in 'AB'))
print('known %d masked %d sample %d, slices %d per variant, name leaks %d -> %s' % (len(known), len(masked), len(sample), nsl, leak, out))
