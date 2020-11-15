#!/usr/bin/python3
from math import sqrt
import random
import sys
from string import ascii_lowercase as alphabet

def index_to_net(i):
    net = ""
    if i == 0:
        return "a"
    while i >= 0:
        letter = alphabet[i % 26]
        i = int(i / 26) - 1
        net = letter + net

    return net

num_nets = int(sys.argv[1])
# This is kind of arbitrary, but seems to matchup with what's done in the parsec inputs
size = int(sqrt(num_nets))
size = size - (size % 100)
size += 200

#Print the first line
print(str(num_nets) + " " + str(size) + " " + str(size))

#Print the nets
for i in range(num_nets):
    # Start with the net id and the "type" which is unused
    line = index_to_net(i) + " 1 "

    # Then add on the inputs to the net
    for j in range(5):
        used_nets = [i]
        # Make sure the inputs aren't itself or a prebious input
        rand = random.randrange(0, num_nets)
        while rand in used_nets:
            rand = random.randrange(0, num_nets)

        line += index_to_net(rand) + " "
        used_nets.append(rand)

    # Finish with END
    line += "END"

    print(line)
