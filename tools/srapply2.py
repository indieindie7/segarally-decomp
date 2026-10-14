# srapply2.py: apply round-2 verdicts to hand_0.txt by address, for every reviewed entry (not only "provisional"
# lines, so sgl_/_N names are covered). Names freed by RENAME are released before new names are given out,
# so swaps (A -> B, A_2 -> A) work without a _2 suffix.
# usage: py -3.13 -I srapply2.py <hand_0.txt> <verdict files>...
import sys, re
hand = sys.argv[1]
act = {}
for rf in sys.argv[2:]:
    for l in open(rf, encoding='utf-8', errors='replace'):
        f = l.split(None, 5)
        if len(f) < 5 or f[3] not in ('CONFIRM', 'RENAME', 'UNSURE'): continue
        if f[3] == 'RENAME' and not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', f[4]): continue
        act[int(f[1], 16)] = (f[3], f[4])
lines = open(hand, encoding='utf-8').read().splitlines()
addr = lambda l: int(l.split()[0], 16)
renamed = {addr(l) for l in lines if act.get(addr(l), ('',))[0] == 'RENAME' and act[addr(l)][1] != l.split()[2]}
used = {l.split()[2] for l in lines if addr(l) not in renamed}
cnt = {'CONFIRM': 0, 'RENAME': 0, 'UNSURE': 0}
out = []
for l in lines:
    f = l.split(' ', 4)
    a = act.get(addr(l))
    if not a:
        out.append(l); continue
    cnt[a[0]] += 1
    rest = f[4] if len(f) > 4 else ''
    if a[0] == 'UNSURE':
        if 'provisional' not in rest: rest = 'provisional ' + rest
        out.append(' '.join(f[:4] + [rest.strip()])); continue
    rest = re.sub(r'\bprovisional\b:?\s*', '', rest).strip()
    nn = f[2]
    if addr(l) in renamed:
        nn = a[1]; k = 2
        while nn in used: nn = '%s_%d' % (a[1], k); k += 1
        used.add(nn)
        rest = (rest + ' (was %s)' % f[2]).strip()
    out.append(' '.join([f[0], f[1], nn, f[3]] + ([rest] if rest else [])))
open(hand, 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
print('confirmed', cnt['CONFIRM'], 'renamed', cnt['RENAME'], 'unsure', cnt['UNSURE'], 'verdicts', len(act))
