#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <errno.h>

#define ADDRESS ((void*)0x7f5707200000ul)
#define REPS 50
#define WAIT_TIME 5

struct hpage {
	volatile char buf[1<<21];
};

static __inline__ unsigned long long rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ((unsigned long long)lo) | (((unsigned long long)hi) << 32);
}

static inline unsigned big_rand() {
	// `rand` is only guaranteed to return 15 bits of randomness, but we
	// need 18. This gives us 30.
	unsigned long r = (rand() << 15) | (rand() & 0x7fff);
	return r;
}

static inline void write_hpage(struct hpage *hpage) {
	// Normal stores
	unsigned long long addr = (unsigned long long)hpage->buf;
	unsigned long long end = addr + (1<<21);

	__asm__ __volatile__ (
		"movq $0xff, %%rax;"
		"write_loop%=:"
		"mov %%rax, (%%rbx);"
		"add $4096, %%rbx;"
		"cmp %%rbx, %%rcx;"
		"jne write_loop%=;"
		: // no outputs
		: "b"(addr), "c"(end)
		: "memory", "%rax", "cc"
	);
}

int main(int argc, const char *argv[]) {
	if (argc < 2) {
		printf("Missing huge flag\n");
		return -1;
	}

	if (argc < 3) {
		printf("Missing size in GB\n");
		return -1;
	}

	clock_t start = clock();
	unsigned long use_hugepages = !!strtoul(argv[1], NULL, 10);
	unsigned long size = strtoul(argv[2], NULL, 10);

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

	long reps = REPS;

	if (argc == 4) {
		reps = strtol(argv[3], NULL, 10);

		if (reps == 0) {
			if (errno == EINVAL) {
				printf("Conversion error occurred: %d\n", errno);
				return -1;
			}
			if (errno == ERANGE) {
				printf("The value provided was out of range\n");
				return -1;
			}
		}

		printf("Using %ld reps.\n", reps);
	}

	printf("Creating a region %lu GB based on hugetlbfs\n", size);

	// Number of huge pages.
	const unsigned long n = size << 9;

	// shm fd
	int fd;

	if (use_hugepages) {
		fd = open("/mnt/huge/foo", O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			perror("unable to open");
			exit(-1);
		}
	} else {
		fd = shm_open("foo", O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd == -1) {
			perror("unable to open");
			exit(-1);
		}

		// Need to ftruncate to 2MB so that there is something to mmap.
		int ret = ftruncate(fd, 1<<21);
		if (ret == -1) {
			perror("unable to ftruncate");
			exit(-1);
		}
	}

	// mmap with huge
	const int mmap_flags = MAP_SHARED | MAP_POPULATE | MAP_FIXED |
		(use_hugepages ? MAP_HUGETLB : 0);

	struct hpage *mem = mmap(ADDRESS, 1ul<<21, PROT_READ | PROT_WRITE, mmap_flags, fd, 0);
	if (mem == MAP_FAILED) {
		perror("unable to mmap");
		exit(-1);
	}
	for (size_t i = 0; i < n; ++i) {
		struct hpage *ptr = mmap(&mem[i], 1ul<<21,
				PROT_READ | PROT_WRITE, mmap_flags, fd, 0);
		if (ptr == MAP_FAILED) {
			perror("unable to sub-mmap");
			exit(-1);
		}
	}

	// Seed prng for reproducibility. We are picking huge pages at random.
	// A huge page is 1<<21 bytes, and we are choosing from a region of
	// `size<<30`, so we want `9 + log(size)` bits of randomness. If we
	// assume that size can be up to terabytes, then we need ~20 or so bits
	// of entropy. `big_rand` returns 30 bits, so that should be enough.
	srand(0);

	// Print status update and sleep before touching pages.
	clock_t elapsed = clock() - start;
	unsigned long elapsed_secs = elapsed / CLOCKS_PER_SEC;
	printf("Created a region %lu GB (%lu huge pages) in %lu seconds. "
		"Waiting %lus.\n",
		size, n, elapsed_secs, WAIT_TIME - elapsed_secs);

	if (elapsed_secs >= WAIT_TIME) {
		printf("Didn't wait long enough!\n");
		exit(-1);
	}

	int ret = sleep(WAIT_TIME - elapsed_secs);
	if (ret != 0) {
		printf("Didn't wait long enough! Sleep interrupted.\n");
		exit(-1);
	}

	unsigned long long start_bmk = rdtsc();

	for (unsigned long i = 0; i < (n * reps); ++i) {
		write_hpage(&mem[big_rand() % n]);

		if (i % (2 * n) == 0) {
			printf("%lu\n", i);
		}
	}

	unsigned long long elapsed_bmk = rdtsc() - start_bmk;

	printf("Done in %llu cycles.\n", elapsed_bmk);
}
