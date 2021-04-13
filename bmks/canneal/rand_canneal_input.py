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

def rand_input(uniform, num_nets):
    if uniform:
        return random.randrange(0, num_nets)
    else:
        mean = int(num_nets/2)
        # Try to fit 3 standard deviations on either side of the mean
        stdev = int(num_nets / 6)
        rand = int(random.normalvariate(mean, stdev))
        while rand > num_nets - 1 or rand < 0:
            rand = int(random.normalvariate(mean, stdev))

        return rand

def calc_num_inputs(rand):
    if rand:
        # Use geometric distrobution with a mean of 5 to determine the number
        # of inputs for this net
        count = 1
        while random.random() < 0.8:
            count += 1
        return count
    else:
        # If we don't want a random number of inputs, just use 5
        return 5

# Get the number of nets to use
num_nets = int(sys.argv[1])

# If there is a second argument, get the distribution
if len(sys.argv) >= 4:
    if sys.argv[2] == "--dist_uniform":
        dist_uniform = True
    elif sys.argv[2] == "--dist_normal":
        dist_uniform = False
    else:
        print("Invalid second argument. Use either --dist_uniform or --dist_normal")
        sys.exit()
else:
    dist_uniform = True

# If there is a third argument, determine if there should be a random number
# of inputs per net
if len(sys.argv) >= 5:
    if sys.argv[3] == "--rand_num_inputs":
        rand_num_inputs = True
    else:
        print("Invalid third argument. Either use --rand_num_inputs or do not "
              "include third argument")
        sys.exit()
else:
    rand_num_inputs = False

# The last argument is the output filename
filename = sys.argv[-1]
f = open(filename, "w")

# This is kind of arbitrary, but seems to matchup with what's done in the parsec inputs
size = int(sqrt(num_nets))
size = size - (size % 100)
size += 200

# Write the first line
f.write(str(num_nets) + " " + str(size) + " " + str(size) + "\n")

#Print the nets
for i in range(num_nets):
    if i % 1000000 == 0:
        print(i)

    num_inputs = calc_num_inputs(rand_num_inputs)

    # Start with the net id and the "type" which is unused
    line = index_to_net(i) + " 1 "

    # Then add on the inputs to the net
    for j in range(num_inputs):
        rand = rand_input(dist_uniform, num_nets)

        line += index_to_net(rand) + " "

    # Finish with END
    line += "END\n"

    f.write(line)

f.close()
