/*
* capi.h
*
*/
#ifndef __CAPI_H
#define __CAPI_H

#ifndef TRUE
#define TRUE 1
#endif	/* TRUE */

typedef struct _capi_pack {
	char *host;
	u_char options;
} capi_pack;

#define CAPI_OPTS	"vnh"
#define CAPI_OPT_NONE	0x0
#define CAPI_OPT_VERB	0x1
#define CAPI_OPT_NOAUTO	0x2

/* cAPI command */
typedef struct _capi_command {
	char *name;		/* User printable name of the function */
	void (*func)(char *);	/* Function to call to do the job */
	char *doc;		/* Documentation for this function */
} capi_command; 

/* cAPI command function prototypes */
void capi_cmd_exit(char *);
void capi_cmd_cookie(char *);
void capi_cmd_get(char *);
void capi_cmd_post(char *);

capi_command *capi_find_cmd(char *);

/* Other */
#define CAPI_VERSION	"0.1"
#define CAPI_AUTHOR	"Jonathan Cormier <jonathan@cormier.co>"
#define CAPI_PROMPT	"cAPI> "

#endif /* __CAPI_H */
