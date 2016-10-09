#!/usr/bin/env python2

# Extract arcfour-hmac-md5 (RC4) hashes from MIT Kerberos, decrypt them
# and convert them to base64 format for unicodePwd attribute in Samba4.
#
# Extract hashes from MIT Kerberos using `kdb5_util dump -b7 dump.mit`.
# Get the kerberos master key: File location is determined by `key_stash_file`
# property in `/var/db/krb5kdc/kdc.conf`. Configure paths (relative or absolute) 
# to these files in `[files]` section in `od2samba4.conf`.
#
# This script requires Heimdal (https://www.h5l.org/). Please change
# `heimdal_path` in `od2samba4.conf` to the directory where the executables
# `hprop` and `hpropd` reside.

from ConfigParser import RawConfigParser
import subprocess
import string
import json
import os

# Parse configuration
config = RawConfigParser()
config.read("od2samba4.conf")

mit_dump = config.get("files", "mit_dump")
master_key = config.get("files", "master_key")
hprop = config.get("files", "heimdal_path") + "/hprop"
hpropd = config.get("files", "heimdal_path") + "/hpropd"
outfile_name = config.get("files", "hashes")

# Convert hashes with heimdal
conv = subprocess.Popen([hprop + " --database=" + mit_dump + " --source=mit-dump --decrypt --master-key=" + master_key + " --stdout | " + hpropd + " -n --print"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
users = conv.stdout.readlines()

# Parse heimdal output, convert from hex to base64, write output file
count = 0
hashes = {}
for user in users:
	attribs = string.split(user, " ")
	username = string.split(attribs[0], "@")[0]
	keys = string.split(attribs[1], ":")
	arcfour_hex = ""

	# arcfour-hmac-md5 is entry type 23
	for i, etype in enumerate(keys):
		if (etype == "23"):
			arcfour_hex = keys[i + 1]
			break

	if (arcfour_hex == ""):
		print("Hash for user " + username + " was not found, ignoring user.")
	else:
		count += 1
		hashes[username] = arcfour_hex.decode("hex").encode("base64").replace("\n", "")

outfile = open(outfile_name, "w")
outfile.write(json.dumps(hashes, indent = 4))
outfile.close()

print(str(count) + " hashes were succesfully extracted and written to " + outfile_name + ".")
