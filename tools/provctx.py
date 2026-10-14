# provctx.py: for each UNSURE review entry, write the function body plus up to 3 caller bodies
# (callers from funcinfo_<P>.tsv C lines), with FUN_<addr> replaced by current hand names.
# usage: py -3.13 -I provctx.py <ghidra> <res_all.txt> <N> <out prefix>
import sys, os, re
g, res, n, pre = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
def bodies(p):
    d = {}; cur = None; buf = []
    for l in open(os.path.join(g, 'decomp_%s.c' % p), encoding='utf-8', errors='replace'):
        m = re.match(r'// ==== (\S+) @ ([0-9a-fA-F]+)', l)
        if m:
            if cur: d[cur] = ''.join(buf)
            cur = m.group(2).lower(); buf = []
        buf.append(l)
    if cur: d[cur] = ''.join(buf)
    return d
def names(p):
    d = {}
    for l in open(os.path.join(g, 'hand_%s.txt' % p), encoding='utf-8', errors='replace'):
        f = l.split(None, 4)
        if len(f) > 2: d[f[0][2:].lower().zfill(8)] = (f[2], f[4].strip() if len(f) > 4 else '')
    return d
def callers(p):
    d = {}; cur = None
    for l in open(os.path.join(g, 'funcinfo_%s.tsv' % p), encoding='utf-8', errors='replace'):
        f = l.split()
        if not f: continue
        if f[0] == 'F': cur = f[1].lower()
        elif f[0] == 'C' and cur: d.setdefault(f[1].lower(), []).append(cur)
    return d
BASE = {'0': 0x06009000}
CD = os.path.join(g, '..', 'saturn', 'cd', 'RALLY')
def image(p):
    for fn in os.listdir(CD):
        if fn.upper() in (p + 'RALLY.DAT',): return open(os.path.join(CD, fn), 'rb').read()
    return b''
def word(img, base, a):
    o = a - base
    return int.from_bytes(img[o:o + 4], 'big') if 0 <= o <= len(img) - 4 else None
def poolcallers(p, img, base, starts):
    # functions whose literal pool (a word inside or right after them) holds the target address
    d = {}
    for o in range(0, len(img) - 3, 2):
        v = int.from_bytes(img[o:o + 4], 'big')
        if v < base or v >= base + len(img): continue
        a = base + o; own = None
        lo, hi = 0, len(starts) - 1
        while lo <= hi:
            m = (lo + hi) // 2
            if starts[m] <= a: own = starts[m]; lo = m + 1
            else: hi = m - 1
        if own is not None: d.setdefault('%08x' % v, set()).add('%08x' % own)
    return d
cache = {}
def ctx(p):
    if p not in cache:
        b, nm, cl = bodies(p), names(p), callers(p)
        img = image(p); base = BASE.get(p, 0x06012000)
        starts = sorted(int(k, 16) for k in nm)
        for k, v in poolcallers(p, img, base, starts).items():
            cl.setdefault(k, []).extend(x for x in v if x != k)
        cache[p] = (b, nm, cl, img, base)
    return cache[p]
def sub(t, nm, img=b'', base=0):
    def ptr(m):
        v = word(img, base, int(m.group(2), 16))
        if v is None: return m.group(0)
        k = '%08x' % v
        return ('&' + nm[k][0]) if k in nm else ('&DAT_' + k if m.group(1) == 'DAT' else '&FUN_' + k)
    t = re.sub(r'PTR_(FUN|DAT|LAB)_([0-9a-fA-F]{8})', ptr, t)
    return re.sub(r'FUN_([0-9a-fA-F]{8})', lambda m: nm.get(m.group(1).lower(), (m.group(0),))[0], t)
items = []
for l in open(res, encoding='utf-8'):
    f = l.split(None, 5)
    if len(f) < 5 or f[3] != 'UNSURE': continue
    p, a = f[0], f[1][2:].lower().zfill(8)
    b, nm, cl, img, base = ctx(p)
    txt = '#### %s 0x%s %s | %s\n' % (p, a, nm.get(a, ('?', ''))[0], nm.get(a, ('', ''))[1])
    ob = sub(b.get(a, '(no body)\n'), nm, img, base).splitlines()
    if len(ob) > 300: ob = ob[:300] + ['  ... (body truncated, %d lines)' % len(ob)]
    txt += '\n'.join(ob) + '\n'
    cs = sorted(set(cl.get(a, [])))
    txt += '---- callers: %d (%s)\n' % (len(cs), ' '.join(nm.get(c, (c,))[0] for c in cs[:12]))
    for c in cs[:3]:
        cb = sub(b.get(c, ''), nm, img, base).splitlines()
        if len(cb) > 80: cb = cb[:80] + ['  ... (caller truncated)']
        txt += '---- caller %s\n%s\n' % (nm.get(c, (c,))[0], '\n'.join(cb))
    items.append(txt)
print('items', len(items))
per = (len(items) + n - 1) // n
for k in range(n):
    open('%s%d.txt' % (pre, k + 1), 'w', encoding='utf-8').write('\n'.join(items[k * per:(k + 1) * per]))
