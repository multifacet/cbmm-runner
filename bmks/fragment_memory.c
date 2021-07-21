#include <strings.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#define GB (1ULL*1024*1024*1024)
#define CACHE_SIZE (8ULL*1024*1024)
#define SUPER   (2ULL*1024*1024)
#define SMALL   (1ULL*512*1024)

#define ERROR_RETURN(ret, msg) ERROR_RETURN_COND(((ret) < 0), msg)
#define ERROR_RETURN_COND(cond, msg) if (cond) {\
    perror("Unable to " msg); \
    return -1; \
}

// Set some system settings.
int settings() {
    int ret;
    pid_t pid = getpid();
    char buf[48];

    ret = system("echo 1 > /proc/sys/vm/overcommit_memory");
    ERROR_RETURN(ret, "set overcommit");

    ret = system("sysctl -w vm.max_map_count=1000000000");
    ERROR_RETURN(ret, "set mmap limit");

    snprintf(buf, 48, "echo -1000 > /proc/%d/oom_score_adj", pid);
    ret = system(buf);
    ERROR_RETURN(ret, "blacklist OOM");

    return 0;
}

// Get the total amount of free memory.
ssize_t total_memory() {
    int ret;
    struct sysinfo info;
    unsigned long total;

    ret = sysinfo(&info);
    ERROR_RETURN(ret, "get sysinfo");

    // Amount of free memory.
    total = info.freeram * info.mem_unit;

    // Round to huge page units...
    total = total & ~(SUPER - 1);

    // Add a bit of fudge factor to avoid OOMing.
    total = 99 * total / 100;

    printf("Detected %ldGB of free memory.\n", total >> 30);

    return total;
}

// Fragment `size` bytes worth of huge pages.
int fragment(size_t size) {
    char *a;
    int ret;

    printf("Ruining %lu bytes (%lu GB) of huge pages.\n", size, size >> 30);

    // mmap the required amount of memory.
    a = mmap(0, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    ERROR_RETURN_COND(a == MAP_FAILED, "mmap");

    printf("mmapped\n");

    // Return all but one page from each huge page... ruining those huge pages.
    for (unsigned long i = 0; i < (size >> 21); ++i) {
        ret = munmap(a + (i<<21), (1<<21) - (1<<12));
        ERROR_RETURN(ret, "munmap");
    }

    printf("munmapped\n");

    return 0;
}

// Force the kernel to reclaim the memory away from the parent process.
int reclaim_memory(ssize_t amount) {
    char *b;
    int ret;

    printf("Reclaiming memory...");

    b = mmap(0, amount, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    ERROR_RETURN_COND(b == MAP_FAILED, "mmap");

    ret = munmap(b, amount);
    ERROR_RETURN(ret, "munmap");

    printf("done\n");

    return 0;
}

int main(int argc, char* argv[]) {
    int percentage, ret;
    size_t size;
    ssize_t total;
    //pid_t pid;
    uid_t uid = geteuid();

    if(argc == 2)
    {
        percentage = atoi(argv[1]);
        if (percentage < 0 || percentage > 100)
            return -2;
    }
    else
    {
        printf("USAGE: ./foo <percent fragmented>\n");
        return -2;
    }

    if (uid != 0) {
        printf("Must run as root!");
        return -2;
    }

    // Set some important settings.
    ret = settings();
    ERROR_RETURN(ret, "munmap");

    // Amount of memory to fragment.
    total = total_memory();
    ERROR_RETURN(ret, "get total memory");
    size = (total * percentage / 100) & ~(SUPER - 1);

    // Map the amount of memory we want to fragment with MAP_POPULATE.
    ret = fragment(size);
    ERROR_RETURN(ret, "fragment memory");

    //// Force the memory to be reallocated somewhere else and then freed.
    //pid = fork();
    //ERROR_RETURN(pid, "fork");

    //if (pid == 0) { // Child
    //    ret = reclaim_memory(total);
    //    return ret;
    //} else {
    //    pid = wait(NULL);
    //    ERROR_RETURN(pid, "wait for child");
    //}

    //printf("Done. Daemonizing and sleeping...\n");
    printf("Done. sleeping...\n");

    // Create sentinel.
    ret = system("touch /tmp/fragmented_sentinel");
    ERROR_RETURN(ret, "touch sentinel");

    //// Daemonize and sleep...
    //ret = daemon(0, 0);
    //ERROR_RETURN(pid, "daemonize");

    while(1) sleep(10000);
}
