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
outjson = {}
for user in users:
	attribs = string.split(user, " ")
	userprops = {}

	# The following types of hashes will be extracted:
	# des-cbc-crc (type 1), des-cbc-md5 (type 3), aes128-cts-hmac-sha1-96 (type 17), aes256-cts-hmac-sha1-96 (type 18), arcfour-hmac-md5 (type 23)
	# types 1, 3, 17, 18 will be used for the "supplementalCredentials" attribute,
	# type 23 will be used for the "unicodePwd" attribute
	# hashlengths stores which hashes to migrate and the length of those hashes in hexadecimal form,
	# which will be checked to make sure the hash matches
	hashlengths = {"1" : 16, "3" : 16, "17" : 32, "18" : 64, "23" : 32}

	keys = string.split(attribs[1], ":")
	for i, etype in enumerate(keys):
		if etype in hashlengths:
			if len(keys[i + 1]) == hashlengths[etype]:
				userprops["type" + etype] = keys[i + 1]

	# Change this if you don't use the NORMAL salt (see kerberos2supplementalCredentials.py for explanation)
	principal = string.split(attribs[0], "@")
	salt = principal[1] + principal[0]
	username = principal[0]
	flags = attribs[9]

	if not userprops:
		print("No hashes for user " + username + " were not found, ignoring user.")
	else:
		userprops["salt"] = salt
		userprops["flags"] = attribs[9]

		outjson[username] = userprops
		count += 1

outfile = open(outfile_name, "w")
outfile.write(json.dumps(outjson, indent = 4))
outfile.close()

print(str(count) + " hashes were succesfully extracted and written to " + outfile_name + ".")
