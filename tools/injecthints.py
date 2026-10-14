# injecthints.py <decomp.c> <hints.txt> <out.c>: put each rules.py hint as "/* decider hint: ... */" under its block header.
import re, sys
h = {}
for l in open(sys.argv[2], encoding='utf-8'):
    p = l.rstrip('\n').split(' ', 2)
    if len(p) == 3 and p[2]: h[int(p[0], 16)] = p[2].replace('*/', '* /')
n = 0
with open(sys.argv[3], 'w', encoding='utf-8') as w:
    for l in open(sys.argv[1], encoding='utf-8', errors='replace'):
        w.write(l)
        m = re.match(r'// ==== \S+ @ ([0-9a-fA-F]+) ', l)
        if m and int(m.group(1), 16) in h:
            w.write('/* decider hint: %s */\n' % h[int(m.group(1), 16)]); n += 1
print('hints injected', n)
