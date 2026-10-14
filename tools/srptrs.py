# words in the binary that point into unowned gap bytes that look like code starts
import sys, collections
d=open(sys.argv[1],'rb').read(); base=int(sys.argv[3],16) if len(sys.argv)>3 else 0x06004000; end=base+len(d)
fs=sorted((int(l.split()[1],16),int(l.split()[4])) for l in open(sys.argv[2]) if l.startswith('F '))
own=bytearray(len(d))
for a,s in fs: own[a-base:a-base+s]=b'\1'*s
ents=set(a for a,_ in fs)
c=collections.Counter()
for i in range(0,len(d)-3,2):
    v=int.from_bytes(d[i:i+4],'big')
    if base<=v<end and v%2==0 and not own[v-base] and v not in ents: c[v]+=1
for v,n in sorted(c.items()):
    h=d[v-base:v-base+4].hex()
    print(hex(v),n,h)
