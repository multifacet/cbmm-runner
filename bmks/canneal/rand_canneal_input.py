#!/usr/bin/python3
from math import sqrt
from multiprocessing import Pool
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

def gen_lines(start, size, num_nets, dist_uniform, seed):
    line = ""
    random.seed(seed)
    for i in range(start, start + size):
        if i % 1000000 == 0:
            print(i)

        num_inputs = calc_num_inputs(False)

        # Start with the net id and the "type" which is unused
        line += index_to_net(i) + " 1 "

        # Then add on the inputs to the net
        for j in range(num_inputs):
            rand = rand_input(dist_uniform, num_nets)

            line += index_to_net(rand) + " "

        # Finish with END
        line += "END\n"

    return line

if __name__ == '__main__':
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

    # If there is a third argument, it will be the seed of the random number generator
    # Otherwise, choose the seed randomly
    if len(sys.argv) >= 5:
        seed = int(sys.argv[3])
    else:
        seed = random.randint(1, 1000000000)

    print("Using seed: " + str(seed))

    # The last argument is the output filename
    filename = sys.argv[-1]
    f = open(filename, "w")

    # This is kind of arbitrary, but seems to matchup with what's done in the parsec inputs
    size = int(sqrt(num_nets))
    size = size - (size % 100)
    size += 200

    # Generate the inputs to the multiprocessing pool
    pool_params = []
    # Split up the work into groups of one million nets
    pool_size = 1000000
    for i in range(0, num_nets, pool_size):
        if i + pool_size > num_nets:
            break
        pool_params.append((i, pool_size, num_nets, dist_uniform, seed + i))
    # Be sure to include any left over nets
    remainder = num_nets % pool_size
    if remainder != 0:
        pool_params.append((num_nets - remainder, remainder, num_nets, dist_uniform, seed - 1))

    # Write the first line
    f.write(str(num_nets) + " " + str(size) + " " + str(size) + "\n")

    with Pool() as p:
        results = p.starmap(gen_lines, pool_params)
        for group in results:
            f.write(group)

    f.close()
