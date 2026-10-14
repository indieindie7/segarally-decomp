"""findbase.py <bin> [step]: guess the load address of a raw SH-2 program: for each candidate base, count 32-bit
literals that point into the image at an SH-2 function prologue (sts.l pr,@-r15 = 4f22, mov.l rN,@-r15 = 2fx6)."""
import sys, struct, collections
b = open(sys.argv[1], 'rb').read()
n = len(b) // 4 * 4
vals = [struct.unpack_from('>I', b, o)[0] for o in range(0, n, 4)]
vals = [v for v in vals if 0x06000000 <= v < 0x06100000 and v % 2 == 0]
def pro(o):
    if o < 0 or o + 2 > len(b): return False
    w = struct.unpack_from('>H', b, o)[0]
    return w == 0x4f22 or (w & 0xf00f) == 0x2f06
score = collections.Counter()
step = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x1000
for base in range(0x06000000, 0x06100000, step):
    score[base] = sum(1 for v in vals if base <= v < base + len(b) and pro(v - base))
for base, s in score.most_common(6): print(hex(base), s)
