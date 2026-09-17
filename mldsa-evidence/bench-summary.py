import collections, statistics, sys
raw = sys.argv[1]
d = collections.defaultdict(list)
loads = []
for line in open(raw):
    parts = line.split()
    if len(parts) != 5:
        continue
    r, imp, op, us, load = parts
    d[(imp, op)].append(float(us))
    loads.append(float(load))
def q(xs, p):
    xs = sorted(xs); k = (len(xs) - 1) * p; f = int(k); c = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[c] - xs[f]) * (k - f)
order = ["aws118", "aws118noavx2", "aws116", "nx", "na", "nc"]
print(f"samples per cell: {len(next(iter(d.values())))}; 1-min loadavg during run: min {min(loads):.1f} median {statistics.median(loads):.1f} max {max(loads):.1f}")
for op in ["keygen", "sign", "verify"]:
    base = statistics.median(d[("aws118", op)])
    print(f"\n{op} (µs/op): median [p10-p90]  vs aws118")
    for imp in order:
        xs = d[(imp, op)]
        m = statistics.median(xs)
        print(f"  {imp:13} {m:8.1f} [{q(xs,0.1):7.1f}-{q(xs,0.9):7.1f}]  {m/base:5.2f}x")
