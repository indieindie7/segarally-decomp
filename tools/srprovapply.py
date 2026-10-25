# srprovapply.py: apply review verdicts to ghidra/hand_0.txt by ADDRESS (Sonic R has one program;
# _2 names are distinct functions, not overlay twins, so name-based provapply.py is wrong here).
# usage: py -3.13 -I srprovapply.py <hand_0.txt> <verdict files>...
# Verdict lines: 0 0x<addr> <old> CONFIRM|RENAME|UNSURE <new> <reason>
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
used = set(l.split()[2] for l in lines if len(l.split()) > 2)
cnt = {'CONFIRM': 0, 'RENAME': 0, 'UNSURE': 0}
out = []
for l in lines:
    f = l.split(' ', 4)
    a = act.get(int(f[0], 16)) if len(f) > 3 else None
    if not a or 'provisional' not in l:
        out.append(l); continue
    cnt[a[0]] += 1
    if a[0] == 'UNSURE':
        out.append(l); continue
    rest = f[4] if len(f) > 4 else ''
    rest = re.sub(r'\bprovisional\b:?\s*', '', rest).strip()
    nn = f[2]
    if a[0] == 'RENAME' and a[1] != f[2]:
        nn = a[1]; k = 2
        while nn in used: nn = '%s_%d' % (a[1], k); k += 1
        used.discard(f[2]); used.add(nn)
        rest = (rest + ' (was %s)' % f[2]).strip()
    out.append(' '.join([f[0], f[1], nn, f[3]] + ([rest] if rest else [])))
open(hand, 'w', encoding='utf-8', newline='\n').write('\n'.join(out) + '\n')
print('confirmed', cnt['CONFIRM'], 'renamed', cnt['RENAME'], 'unsure', cnt['UNSURE'])
