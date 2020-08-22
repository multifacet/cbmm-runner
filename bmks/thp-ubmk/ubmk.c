#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define ADDRESS ((void*)0x7f5707200000ul)

struct hpage {
	char buf[1 << 21];
};

static inline unsigned big_rand() {
	// `rand` is only guaranteed to return 15 bits of randomness, but we
	// need 18. This gives us 30.
	unsigned long r = (rand() << 15) | rand();
	return r;
}

static inline void write_hpage(struct hpage *hpage) {
	for (int i = 0; i < 1<<21; ++i) {
		hpage->buf[i] = 0xff;
	}
}

int main(int argc, const char *argv[]) {
	if (argc < 2) {
		printf("Missing size in GB\n");
		return -1;
	}

	unsigned long size = strtoul(argv[1], NULL, 10);

	if (size == 0) {
		if (errno == EINVAL) {
			printf("Conversion error occurred: %d\n", errno);
			return -1;
		}
		if (errno == ERANGE) {
			printf("The value provided was out of range\n");
			return -1;
		}
	}

	printf("Creating a region %lu GB\n", size);
	
	struct hpage *mem = mmap(ADDRESS, size << 30, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);

	if (mem == MAP_FAILED) {
		perror("Unable to mmap");
		return -1;
	}

	// Seed prng for reproducibility. We are picking huge pages at random.
	// A huge page is 1<<21 bytes, and we are choosing from a region of
	// `size<<30`, so we want `9 + log(size)` bits of randomness. If we
	// assume that size can be up to terabytes, then we need ~20 or so bits
	// of entropy. `big_rand` returns 30 bits, so that should be enough.
	srand(0);

	// Number of huge pages.
	const unsigned long n = size << 9;

	printf("Touching %lu huge pages.\n", n);

	for (unsigned long i = 0; i < n; ++i) {
		write_hpage(&mem[big_rand() % n]);

		if (i % 1000 == 0) {
			printf("%lu\n", i);
		}
	}
}
