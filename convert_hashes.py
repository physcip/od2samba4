#!/usr/bin/env python2

# Convert hashes to LDIF for Samba4 import using ldbmodify.
# Go through list of users on the Samba4 domain controller and generate
# LDIF entry for every user. Passwords of users on the Samba4 server that
# are not found in the hashes file will remain unchanged.

from __future__ import print_function
from ConfigParser import RawConfigParser
import subprocess
import string
import ldap
import json
import math
import time
import sys
import os

k2sc_path = os.path.dirname(os.path.realpath(__file__))

# Parse configuration
config = RawConfigParser()
config.read("od2samba4.conf")

samba4_dc = config.get("samba4", "dc")
samba4_url = config.get("samba4", "url")
samba4_username = config.get("samba4", "username")
samba4_password = config.get("samba4", "password")
hashes_filename = config.get("files", "hashes")
outfile_filename = config.get("files", "hashes_ldif")

# Parse username / hash directory from JSON
injson = json.loads(open(hashes_filename, "r").read())

# Use certificates only for encryption, not authentication (self-signed)
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

# Get user list from Samba4 server
# samba.search_s returns a key-value dictionary dc:uid. We want uid:dc so
# that we can use the uid to find the corresponding hash in JSON hashes file.
samba = ldap.initialize(samba4_url)
samba.set_option(ldap.OPT_REFERRALS, 0)
samba.start_tls_s()
samba.simple_bind_s("cn=" + samba4_username + ",cn=Users," + samba4_dc, samba4_password)
samba_results = samba.search_s("cn=Users," + samba4_dc, ldap.SCOPE_SUBTREE, "(objectclass=person)", ["uid"])
userlist = [(u[1]["uid"][0], u[0]) for u in samba_results if "uid" in u[1]]

# The pwdLastSet time format is an integer that counts the number of 100ns intervals since January 1, 1601 UTC.
# Convert current time from unix epoch to pwdLastSetFormat.
pwdLastSetTime = "{:.0f}".format(math.ceil(time.time() * 10000000) + 116444736000000000)

# Associate hashes with usernames and generate hash-updating LDIF
# `user` is a tuple (uid, dc)
# We don't use ldif.LDIFWriter here since it sorts LDIF attributes alphabetically.
# Samba, however, won't import the LDIF if "replace: <attribute>" isn't mentioned
# before the attribute itself.
outfile = open(outfile_filename, "w")
count = 0

def addModify(dn, key, value, base64=False):
	print("dn: " + dn, file=outfile)
	print("changetype: modify", file=outfile)
	print("replace: " + key, file=outfile)

	# base64 is specified by double colon (::) in LDIF
	print(key + (":: " if base64 else ": ") + value, file=outfile)
	print(file=outfile)

for user in userlist:
	if not user[0] in injson:
		print("No hashes for user " + user[0] + " were found, ignoring.")
	else:
		userprops = injson[user[0]]

		# Enable or disable account according to HDBFlags in Heimdal dump
		# This reads the "invalid" flag of HDBflags, see lib/hdb/hdb.asn1 in Heimdal.
		# If this bit is set to "1", the account will stay disabled.
		#
		# userAccountControl = 512 means UF_NORMAL_ACCOUNT
		# userAccountControl = 514 means UF_NORMAL_ACCOUNT and UF_ACCOUNT_DISABLE
		# After Samba4 import, userAccountControl defaults to 548 which means the account is disabled and no password is required.
		# If the user was enabled in Open Directory, we enable the account only now, so that the system is not vulnerable before password hash migration.
		# If the user was disabled in Open Directory (in the kerberos dump), we set the account to disabled, but migrate all hashes.
		flags_bin = "{0:032b}".format(int(userprops["flags"]))
		account_disabled = (flags_bin[len(flags_bin) - 8] == "1")
		addModify(user[1], "userAccountControl", "514" if account_disabled else "512")

		# Add arcfour hash as "unicodePwd" attribute
		addModify(user[1], "unicodePwd", userprops["type23"].decode("hex").encode("base64").replace("\n", ""), True)

		# Convert type 1, 3, 17, 18 hashes to supplementalCredentials blob using kerberos2supplementalCredentials.py utility
		# If hash types 1 and/or 3 are not provided, create a new "0" hash. This is only to make sure samba accepts the
		# supplementalCredentials blob when importing. Authentication with hashes 1, 3 will be disabled by setting
		# msDS-SupportedEncryptionTypes anyways.
		if not "type1" in userprops:
			userprops["type1"] = "0" * 16
		if not "type3" in userprops:
			userprops["type3"] = "0" * 16

		if len(set(userprops.keys()) & {"type1", "type3", "type17", "type18"}) != 4:
			print("User " + user[0] + ": Not enough hashes for supplementalCredentials, ignoring supplementalCredentials")
		else:
			k2sc_params = " ".join(["--" + e + " " + userprops[e] for e in set(userprops.keys()) & {"type1", "type3", "type17", "type18"}])
			k2sc_popen = subprocess.Popen([k2sc_path + os.sep + "kerberos2supplementalCredentials.py --base64 " + userprops["salt"] + " " + k2sc_params],
					shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			supplementalCredentials = k2sc_popen.stdout.readlines()
			if (not all((d in string.ascii_letters or d in string.digits or d in "+/=\n") for d in supplementalCredentials[0])):
				sys.exit("kerberos2supplementalCredentials.py error:\n" + "".join(supplementalCredentials))
			addModify(user[1], "supplementalCredentials", supplementalCredentials[0].replace("\n", ""), True)

		# Disable authentication with ancient hash formats. Only authentication with arcfour-hmac (23), aes128-cts-hmac-sha1-96 (17) and aes256-cts-hmac-sha1-96 (18)
		# will be supported. This shouldn't be an issue since there really is no need to authenticate with these insecure hashes anymore.
		# Older systems will still be supported by the arcfour-hmac hashes. des-cbc-md5 (3) and des-cbc-crc (1) will be disabled.
		addModify(user[1], "msDS-SupportedEncryptionTypes", str(0b00011100))

		# Change pwdLastSet to current time. Technically, any timestamp != 0 would work if password policy is set to no expiry.
		# The default value 0, however, will cause samba4 to ask for password renewal (NT_STATUS_PASSWORD_MUST_CHANGE).
		# To set at least some meaningful value (since OD doesn't store pwdLastSet), set the current date.
		addModify(user[1], "pwdLastSet", pwdLastSetTime)

		count += 1
		if count % 50 == 0:
			print("Number of converted users: " + str(count))

outfile.close()

print(str(count) + " password hash changes were successfully processed.")
print("Output LDIF was written to " + outfile_filename + ". You can import this into samba4 using:")
print("# ldbmodify " + outfile_filename + " -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0")
print("The control 1.3.6.1.4.1.7165.4.3.12 enables editing of the unicodePwd attribute.")
