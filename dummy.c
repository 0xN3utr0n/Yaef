#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <pthread.h>

#define RED     "\033[31m"
#define RESET   "\033[0m"

void
evil (void)
{
    for (int i = 0; i < 100000; i++)
    {
        printf(RED "\nEvil function !!!\n" RESET);
        sleep(1);
        // Do whatever you want :D
    }

}


int
main (void)
{
    for (int i = 0; i < 1000; i++)
    {
        printf("\nMain function\n");
        sleep(2);
    }

}
