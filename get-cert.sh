#!/bin/sh
#
# get-cert.sh : retrieves SSL certificate from end-point
#
RHOST=$1
RPORT=${2:-443}
CTMP=/tmp/cert.$$.crt
BASENAME=$(basename $0)
OPENSSL=$(which openssl)

# Check for openssl
if [ -z $OPENSSL ]; then
	echo "OpenSSL command line tools are not found."
	exit
fi

# Check for parameters
if [ $# -eq 0 ]; then
	echo "Outputs certificate information to the terminal."
	echo "Usage: $BASENAME <hostname> [port]"

	exit
fi

# Try to obtain certificate 
echo | $OPENSSL s_client -connect ${RHOST}:${RPORT} 2>&1 > ${CTMP}.all
cat ${CTMP}.all | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > $CTMP

# If we have greater than zero (0) file, try to parse it as certificate.
if [ -s $CTMP ]; then
	$OPENSSL x509 -in $CTMP -text | less
fi

# Remove downloaded content
rm -f $CTMP
rm -f ${CTMP}.all
