#!/bin/bash
# Synchronize new users and new group memberships from Open Directory Server to Samba4 Server.
# Overwrite all password hashes on Samba4 server with hashes from Open Directory.
# This script must be executed on the Samba4 server.

set -e

CWD="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Usage: readconfig SECTION KEY
function read_od2s4_config {
python2 << END
from ConfigParser import RawConfigParser
import sys

config = RawConfigParser()
config.read("$CWD" + "/../od2samba4.conf")
print(config.get("$1", "$2"))
END
}

SSHHOST=$(read_od2s4_config opendirectory host)
SSHUSER=$(read_od2s4_config opendirectory sshuser)
SSHPASS=$(read_od2s4_config opendirectory sshpass)
MITDUMP=$(read_od2s4_config files mit_dump)

# Generate MIT KDC password dump on remote Open Directory server and copy file over
echo "Copying MIT Kerberos dump via SSH"
sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no $SSHUSER@$SSHHOST "kdb5_util dump -b7 /tmp/kdc_dump.mit"
sshpass -p "$SSHPASS" scp -o StrictHostKeyChecking=no $SSHUSER@$SSHHOST:/tmp/kdc_dump.mit $CWD/../$MITDUMP
sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no $SSHUSER@$SSHHOST "rm /tmp/kdc_dump.mit"

# Process KDC dump, generate LDIFs for import
# This will not add newly generated groups, but it will establish group membership for new users
cd $CWD/..
./extract_hashes.py
./convert_hashes.py
./convert_users.py -n
./convert_groups.py

# LDIF import
echo "Importing LDIFs into Samba4 AD DC"
echo "Adding new users"
ldbadd -H /var/lib/samba/private/sam.ldb $CWD/../$(read_od2s4_config files newusers_ldif) --relax
echo "Updating hashes"
ldbmodify $CWD/../$(read_od2s4_config files hashes_ldif) -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0
echo "Updating secondary group memberships"
$CWD/../$(read_od2s4_config files membership_script)

