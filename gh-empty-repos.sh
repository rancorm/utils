#!/bin/bash
#
# gh-empty-repos.sh [GitHub empty repository finder]
#
PROGNAME=$0
USERNAME=$1

if [ -z $USERNAME ]; then
	echo "Usage: $PROGNAME <username>"
	exit
fi

GH=(command -v gh)

for REPO in $("$GH" repo list --json name,defaultBranchRef -q '.[].name'); do
	NUMREPO=$("$GH" api "repos/$USERNAME/$REPO/commits?per_page=2" --jq 'length')
	
	if [ "$NUMREPO" -eq 1 ]; then
		echo "$REPO"
	fi
done
