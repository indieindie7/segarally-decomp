"""rules.py: step 2 of the decider. Rule-based names and hints for the functions libmatch left.

    py -3.13 -I rules.py <image> <base hex> <funcinfo.tsv> <libmatch out> <names out> <hints out>

Names (written to <names out>, hand-file lines, merged after the libmatch names):
  stub_<addr>        body is only rts (+ delay slot), returns nothing useful
  ret<N>_<addr>      body only loads a constant into r0 and returns
  <callee>_Wrap      small body (<= 24 bytes) whose only code pointer is one named function (provisional)
Hints (one line per unnamed function, for the Sonnet pass): hardware blocks the body touches (cdc, smpc, vdp1, vdp2,
scu, scsp, cpu), the strings it references, named callees.
"""
import collections, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import libmatch as L

HW = [(0x05890000, 0x058a0000, 'cdc'), (0x00100000, 0x00100080, 'smpc'), (0x05c00000, 0x05d00000, 'vdp1ram'),
      (0x05d00000, 0x05d00020, 'vdp1'), (0x05e00000, 0x05f80000, 'vdp2ram'), (0x05f80000, 0x05f80200, 'vdp2'),
      (0x05fe0000, 0x05fe0100, 'scu'), (0x05a00000, 0x05b00ee4, 'scsp'), (0x01000000, 0x01800000, 'minit'),
      (0x01800000, 0x02000000, 'sinit'), (0x0ffff000, 0x10000000, 'cpu'), (0x00180000, 0x00190000, 'bupram')]


def hw(v):
    v &= 0x1FFFFFFF if (v >> 29) in (1, 5) else 0xFFFFFFFF
    for lo, hi, n in HW:
        if lo <= v < hi: return n
    return None


def main():
    image, base, fi, lm, out, hints = sys.argv[1:7]
    p = L.Prog('t', image, int(base, 16), fi)
    names = {a: n for a, (n, c) in L.load_hand(lm).items()}
    strs, calls, cur = collections.defaultdict(list), collections.defaultdict(list), None
    for l in open(fi, encoding='utf-8', errors='replace'):
        t = l.rstrip('\n').split(' ', 1)
        if t[0] == 'F': cur = int(t[1].split()[0], 16)
        elif t[0] == 'S' and cur is not None and t[1] not in strs[cur]: strs[cur].append(t[1])
        elif t[0] == 'C' and cur is not None: calls[cur].append(int(t[1], 16))
    new = {}
    for a, (n, s) in p.fs.items():
        if a in names: continue
        ops = [p.word(x, 2) for x in range(a, a + s - 1, 2)]
        if ops[:1] == [0x000b] and s <= 4: new[a] = ('stub_%08x' % a, 'empty: rts')
        elif len(ops) == 2 and ops[0] == 0x000b and (ops[1] & 0xFF00) == 0xE000:
            v = ops[1] & 0xFF; v = v - 256 if v > 127 else v
            new[a] = ('ret%s_%08x' % (str(v).replace('-', 'M'), a), 'returns %d' % v)
        elif len(ops) == 2 and ops[1] == 0x000b and (ops[0] & 0xFF00) == 0xE000:
            pass
    used = set(names.values())
    for _ in range(5):                                             # wrappers of named functions, repeated for chains
        for a, (n, s) in p.fs.items():
            if a in names or a in new or s > 24 or a not in p.sig: continue
            tg = {x for x in p.sig[a][1] if x in p.fs} | set(calls[a])
            if len(tg) != 1: continue
            t = tg.pop()
            cn = names.get(t) or (new[t][0] if t in new and not new[t][0].startswith(('stub_', 'ret')) else None)
            if not cn: continue
            nm, k = cn + '_Wrap', 2
            while nm in used: nm = '%s_Wrap%d' % (cn, k); k += 1
            used.add(nm); new[a] = (nm, 'small wrapper around %s' % cn)
    with open(out, 'w', encoding='utf-8') as w:
        for a in sorted(new):
            nm, c = new[a]
            w.write('0x%08x func %s hand %srules: %s\n' % (a, nm, 'provisional ' if nm.endswith(('_Wrap',)) or '_Wrap' in nm else '', c))
    allnames = dict(names); allnames.update({a: v[0] for a, v in new.items()})
    nh = 0
    with open(hints, 'w', encoding='utf-8') as w:
        for a, (n, s) in sorted(p.fs.items()):
            if a in allnames or a not in p.sig: continue
            hb = sorted({h for f in p.sig[a][3] if f.startswith('L') for h in [hw(int(f[1:], 16))] if h})
            cn = sorted({allnames[c] for c in set(calls[a]) | set(p.sig[a][1]) if c in allnames})
            parts = []
            if hb: parts.append('hw=' + ','.join(hb))
            if strs[a]: parts.append('str=' + ' | '.join(strs[a][:4]))
            if cn: parts.append('calls=' + ','.join(cn[:8]))
            w.write('%08x size=%d %s\n' % (a, s, ' '.join(parts))); nh += 1
    kinds = collections.Counter(v[0].split('_')[0] if not v[0].startswith('ret') else 'ret' for v in new.values())
    print('rules: %d names (%s), %d hint lines for the rest -> %s, %s' % (
        len(new), ', '.join('%s %d' % (k, c) for k, c in kinds.most_common(4)) + ', wraps %d' % sum('_Wrap' in v[0] for v in new.values()), nh, out, hints))


if __name__ == '__main__':
    main()
