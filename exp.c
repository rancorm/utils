/*
* Jonathan's certificate validation tool
*
* Exit code indicates if current system date is within certificate notBefore and notAfter.
*
* Usage: exp <path/to/cert/file.pem>
* 
* Example:
*
*   $ ./exp example.crt
*   $ echo $?
*   0
*   $
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <time.h>

#define PROGNAME "exp"

void exp_usage(void) {
  printf("Certificate Validation Tool\n");
  printf("Usage: %s <path/to/cert/file.pem>\n", PROGNAME);
}

int main(int argc, char *argv[]) {
  FILE *fp;
  char *certname;
  X509 *cert;
  const ASN1_TIME *not_after, *not_before;
  int result;

  if (argc == 1) {
    exp_usage();
    exit(EXIT_SUCCESS);
  }
  
  certname = argv[1];

  /* Open file for reading */
  fp = fopen(certname, "r");

  if (fp == NULL) {
    fprintf(stderr, "fopen: failed to open %s\n", certname);

    return 2;
  }

  /* Read PEM content */
  cert = PEM_read_X509(fp, NULL, NULL, NULL);
  if (cert == NULL) {
    fprintf(stderr, "PEM_read_X509: failed to open %s\n", certname);
    fclose(fp);

    return 2;
  }

  /* Get expiration date */
  not_after = X509_get_notAfter(cert);
  result = X509_cmp_current_time(not_after);

  X509_free(cert);
  fclose(fp);

  switch (result) {
    case 0:
      /* Some other error */
      return 2;
    case -1:
      /* Certificate expired */
      return 1;
    default:
      /* Certificate hasn't expired */
      return 0;
  }

  return 0;
}
