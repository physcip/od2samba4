#!/usr/bin/env python2

# Convert Open Directory groups to LDIF for Samba4 import.
# Generates a script that establishes group membership for all users.

from __future__ import print_function
from ConfigParser import RawConfigParser
import ldap
import ldif
import stat
import os

# Parse configuration
config = RawConfigParser()
config.read("od2samba4.conf")

od_password = config.get("opendirectory", "password")
outfile_ldif_name = config.get("files", "groups_ldif")
outfile_script_name = config.get("files", "membership_script")
od_username = config.get("opendirectory", "username")
od_url = config.get("opendirectory", "url")
od_dc = config.get("opendirectory", "dc")
nis_domain = config.get("samba4", "group_nis_domain")
samba4_dc = config.get("samba4", "dc")

# Group attributes that will be retrieved from OD DC (and then processed)
GROUPATTRIBUTES = [
	"gidNumber",			# GID (Group ID)
	"cn",				# Group name (short version)
	"apple-group-realname",		# Group name (long, human-readable version), becomes description in samba4
	"apple-generateduid",		# Becomes objectGUID in samba4
	"memberUid"			# Will be used to generate membership-establishing script and kept for samba4 import
]

# Use certificates only for encryption, not authentication (self-signed)
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

# Connect to open directory
print("Connecting to Open Directory server")
od = ldap.initialize(od_url)
od.simple_bind_s("uid=" + od_username + ",cn=users," + od_dc, od_password)
od_results = od.search_s("cn=groups," + od_dc, ldap.SCOPE_SUBTREE, "(objectclass=posixGroup)", GROUPATTRIBUTES)

# Clean search results: Extract attributes from [(DN, attributes)] list od_results
od_groups = [g[1] for g in od_results]

print("Retrieved group list with " + str(len(od_groups)) + " entries from Open Directory")

# Generate LDIF for import into Samba4 via ldbadd
outfile_ldif = ldif.LDIFWriter(open(outfile_ldif_name, "wb"))
outfile_script = open(outfile_script_name, "w")
print("#!/bin/bash", file = outfile_script)
count = 0
for group in od_groups:
	count += 1
	dn = "CN=" + group["cn"][0] + ",CN=Users," + samba4_dc
	group["objectclass"] = ["top", "group"]
	group["sAMAccountName"] = [group["cn"][0]]
	group["msSFU30Name"] = [group["cn"][0]]
	group["msSFU30NisDomain"] = [nis_domain]

	# Keep `apple-generateduid` from OD, rename to `objectGUID`
	group["objectGUID"] = [group["apple-generateduid"][0]]
	del group["apple-generateduid"]

	# Rename `apple-group-realname` to `description`
	if "apple-group-realname" in group:
		group["description"] = group["apple-group-realname"]
		del group["apple-group-realname"]

	# Process `memberUid` entries: One group usually has several memberUid entries. In samba4,
	# groups will use the `member` attribute to specify all member as DNs. The members of a group
	# will also get a `memberOf` attribute. Instead of modifying all users and converting user UIDs
	# to DNs, the simpler solution is to let samba-tool take care of that by generating a shell script
	# that establishes group membership. We can keep memberUid and also add that to samba4.
	if "memberUid" in group:
		for uid in group["memberUid"]:
			print("samba-tool group addmembers " + group["cn"][0] + " " + uid, file=outfile_script)

	outfile_ldif.unparse(dn, group)

outfile_script.close()
os.chmod(outfile_script_name, os.stat(outfile_script_name).st_mode | stat.S_IEXEC)

print("\nExtracted " + str(count) + " groups into " + outfile_ldif_name +  ".")
print("Copy this file to the samba4 server and import users by executing")
print("# ldbadd -H /var/lib/samba/private/sam.ldb " + outfile_ldif_name + " --relax")
print("Generated " + outfile_script_name + " for establishing group membership.")
print("Copy this script to the samba4 server and apply memberships by executing it.")

