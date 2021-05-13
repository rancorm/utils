#!/bin/sh 
#
# aws-iam-authorized-keys.sh
#
# Copyright (C) 2018 Jonathan Cormier <jonathan@cormier.co>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Last modified: May 12, 2019 (Happy Mothers Day!)
#
# Arguments: $1 (username from sshd)

# Remove inactive SSH keys, disable this only when an inactive SSH key usage is required.
REMOVE_INACTIVE_KEYS=1

# User? Stop! Do not edit below this line without knowledge of how this works.
# Thank you, have a good day.
USERNAME=$1
AWSCLI=/usr/bin/aws
LOGGER=/usr/bin/logger

# No username? We're done.
if [ -z "$USERNAME" ]; then
	exit
fi

SSH_LIST_QUERY="SSHPublicKeys[?Status=='Active'].[SSHPublicKeyId]"

# Query for all keys
if [ $REMOVE_INACTIVE_KEYS -eq 0 ]; then
	SSH_LIST_QUERY="SSHPublicKeys[].[SSHPublicKeyId]"
fi

# List Keys
SSHPUBKEYS=$(					\
	$AWSCLI iam list-ssh-public-keys	\
	--user-name $USERNAME 			\
	--query $SSH_LIST_QUERY			\
	--output text				\
)

# Log users with no keys
if [ -z "$SSHPUBKEYS" ]; then
	$LOGGER --priority authpriv.warn "No SSH public keys found for $USERNAME"
	exit
fi

# Loop through keys, most times only one (1). But, there could be more.
for KEY in $SSHPUBKEYS; do
	# Retrieve SSH public key
	SSHPUBKEY=$(					\
		$AWSCLI iam get-ssh-public-key 		\
		--user-name $USERNAME			\
		--ssh-public-key-id $KEY		\
		--encoding SSH				\
		--output text				\
		--query SSHPublicKey.SSHPublicKeyBody	\
	)

	echo "$SSHPUBKEY"
done
