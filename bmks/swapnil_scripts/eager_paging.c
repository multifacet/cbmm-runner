#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define __NR_eager_paging 436

#define MAX_LEN 15

void showUsage(void);

int main(int argc,char* argv[])
{
	char proc[MAX_LEN + 1];

	if ( argc < 2 )
	{
		showUsage();
		exit(EXIT_SUCCESS);
	}

	strncpy(proc, argv[1], MAX_LEN);
    proc[MAX_LEN] = 0; // null terminate

	syscall(__NR_eager_paging, proc);
	puts(proc);

	return 0;
}

void showUsage(void)
{
	printf("\n Usage : ./eager_paging [proccess_name]\n");
}
