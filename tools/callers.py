import sys,collections
cur=None;names={};callees=collections.defaultdict(set);callers=collections.defaultdict(set)
for l in open('C:/Users/john/Documents/ManxTT/ghidra/funcinfo_0.tsv'):
    p=l.split()
    if not p: continue
    if p[0]=='F': cur=p[1];names[p[1]]=p[2]
    elif p[0]=='C' and cur: callees[cur].add(p[1]);callers[p[1]].add(cur)
def nm(a): return names.get(a,a)+'@'+a
want=sys.argv[1:]
rev={v:k for k,v in names.items()}
for w in want:
    a=rev[w]
    print(w,'<-',sorted(nm(c) for c in callers[a]))
