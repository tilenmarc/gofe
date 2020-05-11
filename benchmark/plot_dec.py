import matplotlib.pyplot as plt
import math

# o = open("times_bernouli.txt")
def table_ddh():
    o = open("benchmark_results_dec_dam.txt")
    values1 = []
    for line in o:
        split = line.split(" ")
        values1.append((split[0], int(split[1]), int(split[2]), int(split[3])/float(1000)))
    o.close()

    o = open("benchmark_results_dmcfe.txt")
    values2 = []
    for line in o:
        split = line.split(" ")
        values2.append((split[0], int(split[1]), int(split[2]), int(split[3])/float(1000)))
    o.close()


    w = open("table_dec.txt", "w")

    for part in ["K1","K2","F","E","D"]:
        w.write(part + "\n")

        l = []
        l2 = []
        l3 = []

        for val in values1:
            if val[0] == part and val[2] == 1000:
                l.append(val[1])
        l = sorted(l)
        for val in l:
            for v1 in values2:
                if v1[0] == part and v1[2] == 1000 and val == v1[1]:
                    l3.append(v1[3])
            for v1 in values1:
                if v1[0] == part and v1[2] == 1000 and val == v1[1]:
                    l2.append(v1[3])

        for i in range(len(l)):
            w.write(str(l[i]) + " & " + str(l2[i]) + " & " + str(l3[i]) + " \\\\ \n")


    for part in ["K1","K2","F","E","D"]:
        w.write(part + "\n")

        l = []
        l2 = []
        l3 = []

        for val in values1:
            if val[0] == part and val[1] == 10:
                l.append(val[2])
        l = sorted(l)
        for val in l:
            for v1 in values2:
                if v1[0] == part and v1[1] == 10 and val == v1[2]:
                    l3.append(v1[3])
            for v1 in values1:
                if v1[0] == part and v1[1] == 10 and val == v1[2]:
                    l2.append(v1[3])

        for i in range(len(l)):
            w.write(str(l[i]) + " & " + str(l2[i]) + " & " + str(l3[i]) + " \\\\ \n")


    w.close()

table_ddh()

















