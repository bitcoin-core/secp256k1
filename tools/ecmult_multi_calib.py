#!/usr/bin/env python3
import sys
from collections import defaultdict

def linreg(x, y):
    n, sx, sy = len(x), sum(x), sum(y)
    sxy, sx2 = sum(a*b for a,b in zip(x,y)), sum(a*a for a in x)
    d = n*sx2 - sx*sx
    if abs(d) < 1e-10: return sy/n, 0
    return (sy - ((n*sxy - sx*sy)/d)*sx)/n, (n*sxy - sx*sy)/d

data = defaultdict(list)
for line in sys.stdin:
    line = line.strip()
    if not line or line.startswith('#'): continue
    p = line.split(',')
    if len(p) == 3: data[p[0]].append((int(p[1]), float(p[2])))

res = {}
for algo, m in data.items():
    if len(m) >= 2:
        C, D = linreg([1.0/n for n,_ in m], [t/n for n,t in m])
        res[algo] = (C, D)

scale = 100.0 / res['PIPPENGER_4'][0] if 'PIPPENGER_4' in res else 1.0

print("static const struct secp256k1_ecmult_multi_abcd secp256k1_ecmult_multi_abcds[SECP256K1_ECMULT_MULTI_NUM_ALGOS] = {")
print("    {0,                                     0,                                     1000,  0     },")
if 'STRAUSS' in res:
    C, D = res['STRAUSS']
    Cs, Ds = max(1,int(C*scale)), max(0,int(D*scale)) if D>0 else 0
    Cstr = f"{Cs},"
    print(f"    {{SECP256K1_STRAUSS_POINT_SIZE,          0,                                     {Cstr:<6} {Ds:<5}}},")
for i in range(1, 13):
    if f'PIPPENGER_{i}' in res:
        C, D = res[f'PIPPENGER_{i}']
        Cs, Ds = max(1,int(C*scale)), max(0,int(D*scale)) if D>0 else 0
        ps = f"SECP256K1_PIPPENGER_POINT_SIZE({i}),"
        fs = f"SECP256K1_PIPPENGER_FIXED_SIZE({i}),"
        Cstr = f"{Cs},"
        print(f"    {{{ps:<35} {fs:<35} {Cstr:<6} {Ds:<5}}},")
print("};")
