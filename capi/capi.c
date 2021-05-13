/*
* capi.c [Command API shell integrator]
*
* Usage: capi [-options] <url>
*
*
* Uses libraries: Readline and cURL
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* cURL */
#include <curl/curl.h>

/* Readline */
#include <readline/readline.h>

/* Jansson */
#include <jansson.h>

#include "capi.h"

/* A static variable for holding the line. */
static char *line_read = (char *)NULL;

/* When non-zero, this global means the user is done using this program. */
int done;

capi_command commands[] = {
	{ "cd", NULL, "Change to directory DIR" },
	{ "exit", capi_cmd_exit, "Exit program" },
	{ "cookie", capi_cmd_cookie, "Work with HTTP cookies" },
	{ "get", capi_cmd_get, "Send GET request" },
	{ "post", capi_cmd_post, "Send POST request" },
  	{ (char *)NULL, (void *)NULL, (char *)NULL }
};

/* Read a string, and return a pointer to it.  Returns NULL on EOF. */
char *
rl_gets() {
	/* free buffer */ 
	if (line_read) {
		free(line_read);
      		line_read = (char *)NULL;
  	}

  	/* get a line from the user. */
  	line_read = readline(CAPI_PROMPT);

  	/* if the line has any text in it, save it on the history. */
  	if (line_read && *line_read) {
  		add_history(line_read);
  	}

	return(line_read);
}

void
capi_cmd(char *name) {
	capi_command *cmd = capi_find_cmd(name);
	
	if (cmd) {
		/* Call the function. */
  		return ((*(cmd->func))(name));
	}
}

void
capi_cmd_post(char *name) {
	return;
}

void
capi_cmd_get(char *name) {
	return;
}

void
capi_cmd_cookie(char *name) {
	printf("Cookies:\n");
}

void
capi_cmd_exit(char *name) {
	done = TRUE;
}

capi_command *
capi_find_cmd(char *name) {
	register int i;

	/* Check for command name */
	for (i = 0; commands[i].name; i++) {
		if (strcmp (name, commands[i].name) == 0)
      			return (&commands[i]);
	}

	return ((capi_command *)NULL);
}

capi_pack *
capi_init(char *host) {
	capi_pack *pack = (capi_pack *)malloc(sizeof(capi_pack));

	if (pack) {
		pack->host = host;
	}

	return pack;
}

void
capi_destroy(capi_pack *pack) {
	if (pack) {
		free(pack);
	}
}

int
main(int argc, char *argv[]) {
	char *line, *hostname;
	capi_pack *pack;

	printf("Welcome to cAPI by %s\n", CAPI_AUTHOR);
	printf("Version: %s\n", CAPI_VERSION);

	hostname = argc == 2 ? argv[1] : "localhost";

	pack = capi_init(hostname);

	/* Loop reading and executing lines until the user quits. */
	for (; done == 0;) {
		line = rl_gets();

		if (!line)
        		break;

		capi_cmd(line);
        }


	/* clean up */
	capi_destroy(pack);
}
