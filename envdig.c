/**
* envdig.c : prints the address/contents/size of every variable in the current environment.
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>

extern char **environ;

/*
* calculates the length of environment variable
* name from environ[], e.g PATH=/usr... will return 4.
*/
size_t envlen(const char *e)
{
    char *p = (char *) strchr(e, '=');
    return (p == NULL ? 0 : p - e);    
}

int main(int argc, char *argv[])
{
    int envc, elen, nbytes, ac;
    char *name, *value;

    printf("envdig [small tool that prints the address of every variable in the current env]\n");
    printf("author: jonathan@cormier.co\n\n");

    for (nbytes = envc = 0; environ[envc]; envc++) {
	elen = envlen(environ[envc]);
	if(elen == 0)
		continue;
	name = strdup(environ[envc]);
        name[elen] = 0;

	value = &environ[envc][elen + 1];
	nbytes += strlen(value);
	printf("%30s @ %p-%p [%s], %d bytes\n", name, value, value+strlen(value), value, strlen(value)); 

	free(name);
    }

    printf("\n");

    ac = argc;
    while(argc-- != 0) {
	printf("%11s%.2d] @ %p-%p [%s], %d bytes\n", "ARGV[", argc, argv[argc], argv[argc]+strlen(argv[argc]), argv[argc], strlen(argv[argc]));
    	nbytes += strlen(argv[argc]);	
    };

    printf("\n%d command-line arguments / %d variables in current environment : %d bytes.\n", ac, envc, nbytes);
    

    /* return() the number of environment variables to the calling shell */
    return (0);
}
