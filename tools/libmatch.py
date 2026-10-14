"""libmatch.py: name SH-2 functions of a new Saturn program by matching them against programs we already named.
No AI: each function body is hashed with its addresses masked, so the same library code (SGL, SBL, GFS, CDC, SMPC,
the C runtime) matches even when it was linked somewhere else. Matches then spread through the call graph: when a
matched function calls X in the reference and Y in the target at the same place, Y gets X's name.

    py -3.13 -I libmatch.py <target image> <base hex> <funcinfo.tsv> <out.txt> [--refs refs.txt] [--skip LABEL]
                            [--eval truth_hand.txt] [--min 12]

refs.txt: one reference per line "label image base funcinfo hand" (paths relative to refs.txt; # comments).
out.txt: hand-file lines "0x<addr> func <name> hand [provisional ]libmatch <how> <label>:<ref addr> | <ref comment>".
  how = body (hash match, every reference that has the body agrees), vote (references disagree, majority),
  call (spread from a matched caller; provisional).
--eval: compare with an existing hand file of the same program (blind test; use --skip to leave that game out of refs).
"""
import argparse, collections, hashlib, os, re, struct, sys

ADDR_HI = set(range(0x0600, 0x0610)) | set(range(0x2600, 0x2610)) | set(range(0x0020, 0x0030)) | set(range(0x2020, 0x2030))
BAD_NAME = re.compile(r'^(FUN_|stub_|unk_|thunk_|LAB_|fn_)|_0[26][0-9a-f]{6}$|^s_')


def load_funcinfo(path):
    fs, cur = {}, None
    for l in open(path, encoding='utf-8', errors='replace'):
        p = l.split()
        if len(p) >= 5 and p[0] == 'F':
            cur = int(p[1], 16); fs[cur] = [p[2], int(p[4])]
    return fs


def load_hand(path):
    out = {}
    for l in open(path, encoding='utf-8', errors='replace'):
        p = l.rstrip('\n').split(None, 4)
        if len(p) >= 3 and p[0].startswith('0x') and p[1] == 'func':
            out[int(p[0], 16)] = (p[2], p[4] if len(p) > 4 else '')
    return out


class Prog:
    def __init__(self, label, image, base, funcinfo, hand=None):
        self.label, self.base = label, base
        self.d = open(image, 'rb').read()
        self.fs = load_funcinfo(funcinfo)
        self.names = {}
        for a, (n, s) in self.fs.items():
            if not n.startswith('FUN_'): self.names[a] = (n, '')
        if hand:
            for a, nc in load_hand(hand).items(): self.names[a] = nc
        self.sig = {}
        for a, (n, s) in self.fs.items():
            r = self.signature(a, s)
            if r: self.sig[a] = r

    def word(self, a, n):
        o = a - self.base
        if o < 0 or o + n > len(self.d): return None
        return struct.unpack_from('>I' if n == 4 else '>H', self.d, o)[0]

    def signature(self, a, s):
        """(hash, ordered list of code addresses this body points at)."""
        o = a - self.base
        if s < 2 or o < 0 or o + s > len(self.d): return None
        h, k, refs, feat = hashlib.sha1(), hashlib.sha1(), [], collections.Counter()
        for pc in range(a, a + s - 1, 2):
            op = self.word(pc, 2)
            hi = op >> 12
            if hi in (0xA, 0xB):                                   # bra / bsr disp12
                disp = op & 0xFFF
                if disp & 0x800: disp -= 0x1000
                if hi == 0xB: refs.append(pc + 4 + disp * 2)
                op &= 0xF000
            elif hi == 0xD or hi == 0x9:                           # mov.l / mov.w @(disp,PC),Rn: hash the value
                disp = op & 0xFF
                if hi == 0xD:
                    v = self.word(((pc + 4) & ~3) + disp * 4, 4)
                    if v is not None and (v >> 16) in ADDR_HI:
                        refs.append(v & 0x0FFFFFFF if (v >> 28) == 2 else v); v = 'A'
                else:
                    v = self.word(pc + 4 + disp * 2, 2)
                h.update(b'%s' % str(v).encode())
                if v != 'A' and v is not None: feat['L%x' % v] += 1
                op &= 0xFF00
            elif (op & 0xFF00) in (0x8900, 0x8B00, 0x8D00, 0x8F00, 0xC700):  # bt bf bt/s bf/s mova
                op &= 0xFF00
            if hi == 0xE: feat['I%d' % (op & 0xFF)] += 1                 # mov #imm
            elif (op & 0xFF00) == 0x8800: feat['Q%d' % (op & 0xFF)] += 1 # cmp/eq #imm
            elif (op & 0xF0FF) == 0x400B: feat['J'] += 1                # jsr
            h.update(struct.pack('>H', op)); k.update(struct.pack('>H', op))
        return h.hexdigest()[:16], refs, k.hexdigest()[:16], feat


def good(n):
    return not BAD_NAME.search(n)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('image'); ap.add_argument('base'); ap.add_argument('funcinfo'); ap.add_argument('out')
    ap.add_argument('--refs', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'refs.txt'))
    ap.add_argument('--skip', action='append', default=[]); ap.add_argument('--eval'); ap.add_argument('--min', type=int, default=12)
    ap.add_argument('--fuzzy', type=float, default=0, help='fuzzy tier threshold, e.g. 0.5 (0 = off)')
    a = ap.parse_args()
    tgt = Prog('target', a.image, int(a.base, 16), a.funcinfo)
    refs, rd = [], os.path.dirname(os.path.abspath(a.refs))
    for l in open(a.refs, encoding='utf-8'):
        p = l.split('#')[0].split()
        if len(p) < 5 or any(p[0].startswith(s) for s in a.skip): continue
        j = lambda x: x if os.path.isabs(x) else os.path.join(rd, x)
        refs.append(Prog(p[0], j(p[1]), int(p[2], 16), j(p[3]), j(p[4])))
    print('target %d fn; refs: %s' % (len(tgt.fs), ', '.join('%s %d/%d' % (r.label, len(r.names), len(r.fs)) for r in refs)))

    # hash -> list of (ref, addr); per ref, a hash that occurs twice with different names is ambiguous there
    by_hash = collections.defaultdict(list)
    for r in refs:
        for ad, (hs, *_) in r.sig.items():
            if r.fs[ad][1] >= a.min: by_hash[hs].append((r, ad))
    tcount = collections.Counter(v[0] for v in tgt.sig.values())
    got = {}                                                       # target addr -> (name, how, ref, refaddr, comment)
    pairs = []                                                     # (target addr, ref, ref addr) for call spreading
    for ad, (hs, *_) in tgt.sig.items():
        if tgt.fs[ad][1] < a.min or hs not in by_hash or tcount[hs] > 1: continue
        votes = collections.Counter()
        for r, ra in by_hash[hs]:
            if ra in r.names and good(r.names[ra][0]): votes[r.names[ra][0]] += 1
        for r, ra in by_hash[hs]: pairs.append((ad, r, ra))
        if not votes: continue
        (name, nv), tot = votes.most_common(1)[0], sum(votes.values())
        if len(votes) > 1 and nv * 2 <= tot: continue                 # no majority
        r, ra = next((r, ra) for r, ra in by_hash[hs] if r.names.get(ra, ('',))[0] == name)
        got[ad] = (name, 'body' if len(votes) == 1 else 'vote', r.label, ra, r.names[ra][1])

    # fuzzy tier: code built by another compiler. Compare the constants a body uses (literal-pool values, mov/cmp
    # immediates, call count), weighted by rarity; take the best reference body when it clearly beats the rest.
    if a.fuzzy:
        import math
        cands = [(r, ra) for r in refs for ra in r.sig if r.fs[ra][1] >= 24 and ra in r.names and good(r.names[ra][0])]
        df = collections.Counter(f for r, ra in cands for f in r.sig[ra][3])
        idf = {f: math.log(len(cands) / c) for f, c in df.items()}
        inv = collections.defaultdict(list)
        for i, (r, ra) in enumerate(cands):
            for f in r.sig[ra][3]:
                if df[f] < len(cands) * 0.05: inv[f].append(i)
        def score(fa, fb):
            ks = fa.keys() | fb.keys()
            num = sum(min(fa[f], fb[f]) * idf.get(f, 5) for f in ks)
            den = sum(max(fa[f], fb[f]) * idf.get(f, 5) for f in ks)
            return num / den if den else 0
        for ad, sg in tgt.sig.items():
            if ad in got or tgt.fs[ad][1] < 24: continue
            ft = sg[3]
            if sum(idf.get(f, 5) for f in ft if df[f] < len(cands) * 0.05) < 8: continue   # too little evidence
            ids = {i for f in ft for i in inv.get(f, ())}
            sc = sorted(((score(ft, cands[i][0].sig[cands[i][1]][3]), i) for i in ids), reverse=True)
            if not sc or sc[0][0] < a.fuzzy: continue
            r, ra = cands[sc[0][1]]
            name = r.names[ra][0]
            rival = next((x for x, i in sc[1:] if cands[i][0].names[cands[i][1]][0].split('_')[0] != name.split('_')[0]), 0)
            if rival > sc[0][0] * 0.85: continue
            got[ad] = (name, 'fuzzy', r.label, ra, r.names[ra][1]); pairs.append((ad, r, ra))

    # spread through calls: same-position code pointers of matched pairs
    rounds = 0
    while True:
        rounds += 1
        prop = collections.defaultdict(collections.Counter)
        src = {}
        for ad, r, ra in pairs:
            tr, rr = tgt.sig[ad][1], r.sig[ra][1]
            if len(tr) != len(rr): continue
            for x, y in zip(tr, rr):
                if x in tgt.fs and x not in got and y in r.names and good(r.names[y][0]):
                    prop[x][r.names[y][0]] += 1; src[(x, r.names[y][0])] = (r, y)
        new = 0
        for x, c in prop.items():
            (name, nv) = c.most_common(1)[0]
            if len(c) > 1 and nv * 2 <= sum(c.values()): continue
            r, y = src[(x, name)]
            got[x] = (name, 'call', r.label, y, r.names[y][1]); new += 1
            pairs.append((x, r, y)) if x in tgt.sig and y in r.sig else None
        if not new or rounds > 20: break

    used, lines = collections.Counter(), []
    for ad in sorted(got):
        name, how, lab, ra, com = got[ad]
        used[name] += 1
        if used[name] > 1: name = '%s_%d' % (name, used[name])
        got[ad] = (name, how, lab, ra, com)
        lines.append('0x%08x func %s hand %slibmatch %s %s:%08x | %s' % (ad, name, 'provisional ' if how != 'body' else '', how, lab, ra, com))
    open(a.out, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
    hc = collections.Counter(g[1] for g in got.values())
    big = sum(1 for x in tgt.fs if tgt.fs[x][1] >= a.min)
    print('named %d of %d (%d of %d >= %d bytes): %s; spread rounds %d -> %s' % (
        len(got), len(tgt.fs), sum(1 for x in got if tgt.fs[x][1] >= a.min), big, a.min, dict(hc), rounds, a.out))

    if a.eval:
        truth = load_hand(a.eval)
        words = lambda n: {w.lower() for w in re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+', re.sub(r'_\d+$', '', n))}
        pre = lambda n: n.split('_')[0].lower()
        st = collections.defaultdict(lambda: [0, 0, 0, 0.0])
        rows = []
        for ad, (name, how, lab, ra, com) in got.items():
            if ad not in truth: continue
            t = truth[ad][0]
            ov = len(words(t) & words(name)) / max(len(words(t) | words(name)), 1)
            s = st[how]; s[0] += 1; s[1] += re.sub(r'_\d+$', '', t) == re.sub(r'_\d+$', '', name); s[2] += pre(t) == pre(name); s[3] += ov
            rows.append((ov, ad, how, t, name))
        for how, (n, ex, pr, ov) in sorted(st.items()):
            print('eval %-5s n=%4d exact %4d  same prefix %4d  mean word overlap %.2f' % (how, n, ex, pr, ov / max(n, 1)))
        with open(a.out + '.eval', 'w', encoding='utf-8') as w:
            for ov, ad, how, t, name in sorted(rows):
                w.write('%.2f %08x %-5s %-36s %s\n' % (ov, ad, how, t, name))


if __name__ == '__main__':
    main()
