#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define FILE_NAME_SIZE 128

int main(int argc, char *argv[])
{
    char *filter_file_name;
    char *program_name;
    char *filebuf;
    char mmap_filters_name[FILE_NAME_SIZE];
    FILE* filter_file;
    FILE* mmap_filters_file;
    int len;
    int count = 0;
    int ret;
    pid_t pid;

    // Check if there are enough arguments
    if (argc < 3) {
        fprintf(stderr, "Usage: cb_wrapper <filter_file> <program> [args..]\n");
        return -1;
    }

    filter_file_name = argv[1];
    program_name = argv[2];

    pid = getpid();

    // Construct the filepath of the mmap_filters file
    snprintf(mmap_filters_name, FILE_NAME_SIZE, "/proc/%d/mmap_filters", pid);

    // Open the relevant files
    filter_file = fopen(filter_file_name, "r");
    if (!filter_file) {
        fprintf(stderr, "Could not open %s\n", filter_file_name);
        return -1;
    }

    mmap_filters_file = fopen(mmap_filters_name, "w");
    if (!mmap_filters_file) {
        fprintf(stderr, "Could not open %s\n", mmap_filters_name);
        return -1;
    }

    // Get the length of the input file
    fseek(filter_file, 0, SEEK_END);
    len = ftell(filter_file);
    rewind(filter_file);

    filebuf = malloc(sizeof(char) * len);
    if (!filebuf) {
        fprintf(stderr, "Out of memory\n");
        return -1;
    }

    // Read in the entire filter file because we need to write to
    // mmap_filters all at once
    ret = fread(filebuf, sizeof(char), len, filter_file);
    if (ret != len) {
        fprintf(stderr, "Read in %d bytes. Expected %d\n", ret, len);
        return -1;
    }

    // Write to the mmap_filters file
    ret = fwrite(filebuf, sizeof(char), len, filter_file);
    if (ret != len) {
        fprintf(stderr, "Wrote %d bytes. Expected %d\n", ret, len);
    }

    fclose(filter_file);
    fclose(mmap_filters_file);

    printf("Starting process with pid %d\n", pid);

    // Execute the intended program
    execv(program_name, &argv[2]);

    // We only get here if execv failed
    fprintf(stderr, "Failed to execute %s\n", program_name);
    return -1;
}
