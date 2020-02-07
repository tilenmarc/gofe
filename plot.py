import matplotlib.pyplot as plt
import math

# o = open("times_bernouli.txt")
o = open("sample/times.txt")
o = open("innerprod/fullysec/times_pailier.txt")
x, y, z = [], [], []
points = []
for line in o:
    split = line.split(" ")
    points.append([int(split[0]), int(split[1])])
    # x.append(int(split[0]))
    # y.append(int(split[1]))
# print(x, y)

d = {}
d_avg = {}
for e in points:
    if e[0] not in d:
        d[e[0]] = [e[1]]
    else:
        d[e[0]].append(e[1])

for key in d:
    avg = sum(d[key]) / float(len(d[key]))
    d_avg[key] = avg

# print(d_avg)
for key in sorted(d_avg):
    # x.append(key)
    u = math.sqrt(key)
    uu = int(math.log(u, 2))
    x.append("2^" + str(uu))
    y.append(d_avg[key])
    z.append(len(d[key]))

plt.plot(x, y, "ro")
plt.axis([0, 20, 11000, 12000])
plt.show()

plt.plot(x, z, 'ro')
plt.show()
