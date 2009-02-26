#include <string.h>
#include <stdio.h>


int main(int argc, char *argv[]){
printf("Hello world, %d\n", getpid());
fflush(stdout);
sleep(5);
int *x = 0;
*x = 69;
}

