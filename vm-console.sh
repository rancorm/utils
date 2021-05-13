#!/bin/sh
#
# vm-console.sh
#
DOMID=$(xe vm-list uuid=$1 params=dom-id --minimal)
HOSTUUID=$(xe vm-list uuid=$1 params=resident-on --minimal)
NAMELABEL=$(xe host-list uuid=$HOSTUUID params=name-label --minimal)
XL=$(which xl)
MYHOSTNAME=$(hostname)

if [ "${MYHOSTNAME}-" == "${NAMELABEL}-" ]; then
        echo "locally resident"
        
	ps aux | grep vnc | grep "/$DOMID/" | awk '{print $2}' | xargs kill >/dev/null 2>/dev/null
        echo "Connecting, use Ctrl-] to disconnect."
        
	$XL console $DOMID
else
        echo "resident on $NAMELABEL, domid=$DOMID"
fi
