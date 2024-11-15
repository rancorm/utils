/*
* Jonathan's certificate output tool
*
* Usage: pem <path/to/cert/file.pem>
*
* Reads X.509 certificate and prints details to stdout, same
* as openssl x509 -text...
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

#define PROGNAME "pem"

void pem_usage(void) {
  printf("Certificate Output Tool\n");
  printf("Usage: %s <path/to/cert/file.pem>\n", PROGNAME);
}

int main(int argc, char *argv[]) {
  FILE *fp;
  char *certname;
  X509 *cert;

  if (argc == 1) {
    pem_usage();
    exit(EXIT_SUCCESS);
  }
  
  certname = argv[1];

  /* Open file for reading */
  fp = fopen(certname, "r");

  if (fp == NULL) {
    fprintf(stderr, "fopen: failed to open %s\n", certname);

    return 1;
  }

  /* Read PEM content */
  cert = PEM_read_X509(fp, NULL, NULL, NULL);
  if (cert == NULL) {
    fprintf(stderr, "PEM_read_X509: failed to open %s\n", certname);
    fclose(fp);

    return 1;
  }

  X509_print_fp(stdout, cert);
  X509_free(cert);
  fclose(fp);

  return 0;
}
