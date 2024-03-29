#include <sys/mman.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#define ADDRESS ((void*)0x7f5707200000ul)
#define REPS 50

#define WAIT_TIME_PER_100GB 65.0 // seconds

struct hpage {
	char buf[1 << 21];
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

static inline void read_hpage(struct hpage *hpage) {
	// Normal loads
	unsigned long long addr = (unsigned long long)hpage->buf;
	unsigned long long end = addr + (1<<21);

	__asm__ __volatile__ (
		"read_loop%=:"
		"mov (%%rbx), %%rax;"
		"add $4096, %%rbx;"
		"cmp %%rbx, %%rcx;"
		"jne read_loop%=;"
		: // no outputs
		: "b"(addr), "c"(end)
		: "memory", "%rax", "cc"
	);
}

static inline void write_hpage(struct hpage *hpage) {
	// Naive C implementation
	//for (int i = 0; i < 1<<21; i+=1<<12) {
	//	hpage->buf[i] = 0xff;
	//}

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

	// 50% loads-stores
	//unsigned long long addr = (unsigned long long)hpage->buf;
	//unsigned long long end = addr + (1<<21);
	//
	//__asm__ __volatile__ (
	//	"movq $0xff, %%rax;"
	//	"loop:"
	//	"mov %%rax, (%%rbx);" // store
	//	"add $4096, %%rbx;"
	//	"mov (%%rbx), %%rdx;" // load
	//	"add $4096, %%rbx;"
	//	"cmp %%rbx, %%rcx;"
	//	"jne loop;"
	//	: // no outputs
	//	: "b"(addr), "c"(end)
	//	: "memory", "%rax", "%rdx", "cc"
	//);

	// Non-temporal stores
	//unsigned long long addr = (unsigned long long)hpage->buf;
	//unsigned long long end = addr + (1<<21);
	//
	//__asm__ __volatile__ (
	//	"movq $0xff, %%rax;"
	//	"loop:"
	//	"movnti %%rax, (%%rbx);"
	//	"add $4096, %%rbx;"
	//	"cmp %%rbx, %%rcx;"
	//	"jne loop;"
	//	: // no outputs
	//	: "b"(addr), "c"(end)
	//	: "memory", "%rax", "cc"
	//);
}

int main(int argc, const char *argv[]) {
	if (argc < 2) {
		printf("Missing size in GB\n");
		return -1;
	}

	clock_t start = clock();
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

	long reps = REPS;

	if (argc == 3) {
		reps = strtol(argv[2], NULL, 10);

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

	int uninstrumented = !!getenv("THP_UBMK_UNINSTRUMENTED");

	printf("Creating a region %lu GB\n", size);

	struct hpage *mem = mmap(ADDRESS, size << 30, PROT_WRITE | PROT_READ,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);

	if (mem == MAP_FAILED) {
		perror("Unable to mmap");
		return -1;
	}

	// Number of huge pages.
	const unsigned long n = size << 9;
	const unsigned int wait_time = WAIT_TIME_PER_100GB * size / 100.0 + 1;

	//for (unsigned long i = 0; i < n; ++i) {
	//	write_hpage(&mem[i]);
	//}

	// Seed prng for reproducibility. We are picking huge pages at random.
	// A huge page is 1<<21 bytes, and we are choosing from a region of
	// `size<<30`, so we want `9 + log(size)` bits of randomness. If we
	// assume that size can be up to terabytes, then we need ~20 or so bits
	// of entropy. `big_rand` returns 30 bits, so that should be enough.
	srand(0);

	// Print status update and sleep before touching pages.
	clock_t elapsed = clock() - start;
	unsigned long elapsed_secs = elapsed / CLOCKS_PER_SEC;
	if (uninstrumented) {
		printf("Created a region %lu GB (%lu huge pages) in %lu seconds. "
			"NOT waiting... uninstrumented.\n",
			size, n, elapsed_secs);
	} else {
		printf("Created a region %lu GB (%lu huge pages) in %lu seconds. "
			"Waiting %lus.\n",
			size, n, elapsed_secs, wait_time - elapsed_secs);

		if (elapsed_secs >= wait_time) {
			printf("Didn't wait long enough!\n");
			exit(-1);
		}

		int ret = sleep(wait_time - elapsed_secs);
		if (ret != 0) {
			printf("Didn't wait long enough! Sleep interrupted.\n");
			exit(-1);
		}
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
