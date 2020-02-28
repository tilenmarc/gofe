import matplotlib.pyplot as plt
import math

# o = open("times_bernouli.txt")
o = open("benchmark_results_damgard.txt")
values = {}
for line in o:
    split = line.split(" ")
    values[split[0], int(split[1]), int(split[2])] = int(split[3])
o.close()

x, y = [], []
for key in values:
    if key[0] != "D":
        continue

    x.append(key[1])
    y.append(values[key] / float(1000000))

plt.plot(x, y, "ro")

o = open("benchmark_results_ec.txt")
values = {}
for line in o:
    split = line.split(" ")
    values[split[0], int(split[1]), int(split[2])] = int(split[3])
o.close()

x, y = [], []
for key in values:
    if key[0] != "D":
        continue

    x.append(key[1])
    y.append(values[key] / float(1000000))

plt.plot(x, y, "bo")
# plt.axis([0, 20, 11000, 12000])
plt.show()

