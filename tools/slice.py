# slice.py: split a CsDumpAll dump into N files of whole functions, for naming agents.
# usage: py -3.13 -I slice.py <decomp.c> <N> <out prefix> [hand file]
# Keeps only functions whose dump name is FUN_ and whose address is not in the hand file.
# Slices are cut in address order with about equal line counts. Prints "<file> <functions> <lines>".
import sys, os, re
src, n, pre = sys.argv[1], int(sys.argv[2]), sys.argv[3]
done = set()
if len(sys.argv) > 4 and os.path.exists(sys.argv[4]):
    for l in open(sys.argv[4], encoding='utf-8'):
        m = re.match(r'0x([0-9a-fA-F]+) ', l)
        if m: done.add(int(m.group(1), 16))
funcs, cur = [], None
for l in open(src, encoding='utf-8', errors='replace'):
    m = re.match(r'// ==== (\S+) @ ([0-9a-fA-F]+)', l)
    if m:
        cur = [m.group(1), int(m.group(2), 16), [l]]; funcs.append(cur)
    elif cur: cur[2].append(l)
keep = [f for f in funcs if f[0].startswith('FUN_') and f[1] not in done]
total = sum(len(f[2]) for f in keep)
per = total / n
out, acc, k = [[] for _ in range(n)], 0, 0
for f in keep:
    if acc >= per * (k + 1) and k < n - 1: k += 1
    out[k].append(f); acc += len(f[2])
for i, fl in enumerate(out):
    fn = f'{pre}{i + 1}.c'
    with open(fn, 'w', encoding='utf-8') as w:
        for f in fl: w.writelines(f[2])
    print(fn, len(fl), sum(len(f[2]) for f in fl))
