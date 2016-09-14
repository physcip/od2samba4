#!/usr/bin/env python2

# Convert hashes to LDIF for Samba4 import using ldbmodify.
# Go through list of users on the Samba4 domain controller and generate
# LDIF entry for every user. Passwords of users on the Samba4 server that
# are not found in the hashes file will remain unchanged.

from __future__ import print_function
from ConfigParser import SafeConfigParser
import ldap
import json
import math
import time

# Parse configuration
config = SafeConfigParser()
config.read("od2samba4.conf")

samba4_dc = config.get("samba4", "dc")
samba4_url = config.get("samba4", "url")
samba4_username = config.get("samba4", "username")
samba4_password = config.get("samba4", "password")
hashes_filename = config.get("files", "hashes")
outfile_filename = config.get("files", "hashes_ldif")

# Parse username / hash directory from JSON
hashes = json.loads(open(hashes_filename, "r").read())

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
	print(key + (":: " if base64 else ": ") + value, file=outfile)
	print(file=outfile)

for user in userlist:
	if not user[0] in hashes:
		print("Hash for user " + user[0] + " was not found, ignoring.")
	else:
		count += 1

		# base64 is specified by double colon (::) in LDIF
		addModify(user[1], "unicodePwd", hashes[user[0]], True)

		# userAccountControl = 512 means UF_NORMAL_ACCOUNT
		# After Samba4 import, userAccountControl defaults to 548 which means the account is disabled and no password is required.
		# We only enable the account now, so that the system is not vulnerable before password hash migration.
		addModify(user[1], "userAccountControl", "512")

		# Change pwdLastSet to current time. Technically, any timestamp != 0 would work if password policy is set to no expiry.
		# The default value 0, however, will cause samba4 to ask for password renewal (NT_STATUS_PASSWORD_MUST_CHANGE).
		# To set at least some meaningful value (since OD doesn't store pwdLastSet), set the current date.
		addModify(user[1], "pwdLastSet", pwdLastSetTime)

outfile.close()

print(str(count) + " password hash changes were successfully processed.")
print("Output LDIF was written to " + outfile_filename + ". You can import this into Samba4 using:")
print("# ldbmodify " + outfile_filename + " -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0")
print("The control 1.3.6.1.4.1.7165.4.3.12 enables editing of the unicodePwd attribute.")
