#!/usr/bin/env python2

# Convert Open Directory groups to LDIF for Samba4 import.
# Generates a script that establishes secondary group membership for all users.

from __future__ import print_function
from ConfigParser import RawConfigParser
from optparse import OptionParser
import struct
import ldap
import ldif
import stat
import json
import os

# Parse command line options
parser = OptionParser()
parser.add_option("-a", "--amend-nis-props", action="store_true", default = False, help = "Amend NIS Domain, NIS Name and gidNumber attribute to existing AD system groups")
(cmdline_opts, args) = parser.parse_args()

# Parse configuration
config = RawConfigParser()
config.read("od2samba4.conf")

od_password = config.get("opendirectory", "password")
outfile_ldif_name = config.get("files", "groups_ldif")
outfile_script_name = config.get("files", "membership_script")
od_username = config.get("opendirectory", "username")
od_url = config.get("opendirectory", "url")
od_dc = config.get("opendirectory", "dc")
samba4_dc = config.get("samba4", "dc")
samba4_url = config.get("samba4", "url")
samba4_username = config.get("samba4", "username")
samba4_password = config.get("samba4", "password")
nis_domain = config.get("samba4", "nis_domain")

# Parse JSON that defines what to do with groups (migrate or merge)
groupactions = json.loads(open("groups.json", "r").read())

# Group attributes that will be retrieved from OD DC (and then processed)
GROUPATTRIBUTES = [
	"gidNumber",			# GID (Group ID)
	"cn",				# Group name (short version)
	"apple-group-realname",		# Group name (long, human-readable version), becomes description in samba4
	"apple-generateduid",		# Becomes objectGUID in samba4
	"memberUid",			# Will be used to generate secondary membership-establishing script and kept for samba4 import
	"apple-group-nestedgroup"	# Used to replicate nested group structure on Samba4 AD DC
]

# Use certificates only for encryption, not authentication (self-signed)
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

# Connect to Open Directory
print("Connecting to Open Directory server")
od = ldap.initialize(od_url)
od.simple_bind_s("uid=" + od_username + ",cn=users," + od_dc, od_password)
od_results = od.search_s("cn=groups," + od_dc, ldap.SCOPE_SUBTREE, "(objectclass=posixGroup)", GROUPATTRIBUTES)

# If command line option -a / --amend-nis-props is used, amend existing samba groups with NIS Domain, NIS Name and a gidNumber matching
# the group's RID (= last Block of objectSid = number used for primaryGroupID). Connect to Samba4 server to retrieve a list of existing groups.
samba4_sysgroups = {}
if cmdline_opts.amend_nis_props:
	print("Connecting to Samba4 server")
	samba = ldap.initialize(samba4_url)
	samba.set_option(ldap.OPT_REFERRALS, 0)
	samba.start_tls_s()
	samba.simple_bind_s("cn=" + samba4_username + ",cn=Users," + samba4_dc, samba4_password)

	samba_results = samba.search_s("cn=Users," + samba4_dc, ldap.SCOPE_SUBTREE, "(objectclass=group)", ["cn", "objectSid"])
	groupslist = [g[1] for g in samba_results]
	for sysgroup in groupslist:
		samba4_sysgroups[sysgroup["cn"][0]] = struct.unpack("<i", sysgroup["objectSid"][0][-4:])[0]
	print("Retrieved list of " + str(len(groupslist)) + " existing groups from Samba4")

# Clean search results: Extract attributes from [(DN, attributes)] list od_results
# Delete all groups that are not going to be migrated / merged from list
od_groups = [g[1] for g in od_results]
print("Retrieved group list with " + str(len(od_groups)) + " entries from Open Directory")
od_groups = [g for g in od_groups if g["cn"][0] in groupactions]

def write_replace(fd, key, value):
	print("-", file = fd)
	print("replace: " + key, file = fd)
	print(key + ": " + value, file = fd)

# Generate LDIF for import into Samba4 via ldbadd
# Writing the LDIF manually (instead of using LDIFWriter) is simpler in this case.
outfile_ldif = open(outfile_ldif_name, "wb")
outfile_script = open(outfile_script_name, "w")
print("#!/bin/bash", file = outfile_script)
od_count = 0
for group in od_groups:
	if not group["cn"][0] in groupactions:
		continue

	print("Processing group " + group["cn"][0])

	target = groupactions[group["cn"][0]]["target"]
	actiontype = groupactions[group["cn"][0]]["type"]

	print("dn: CN=" + target + ",CN=Users," + samba4_dc, file = outfile_ldif)
	group["msSFU30Name"] = [target]
	group["msSFU30NisDomain"] = [nis_domain]

	# Process `memberUid` entries: One group usually has several memberUid entries. In Samba4,
	# groups use the `member` attribute to specify all member as DNs. The members of a group
	# will also get a `memberOf` attribute. Instead of modifying all users and converting user UIDs
	# to DNs, the simpler solution is to let samba-tool take care of that by generating a shell script
	# that establishes group membership. We can keep the memberUid attribute and also add that to Samba4.
	if "memberUid" in group:
		for uid in group["memberUid"]:
			print("samba-tool group addmembers \"" + target + "\" \"" + uid + "\"", file = outfile_script)
		del group["memberUid"]

	# Look for nested (children) groups
	# Only if the child group is also being migrated / merged, it will be added as
	# a member to this group.
	if "apple-group-nestedgroup" in group:
		for nested in group["apple-group-nestedgroup"]:
			for child in od_groups:
				if child["apple-generateduid"][0] == nested:
					print("--> Has child: " + child["cn"][0])
					print("samba-tool group addmembers \"" + target + "\" \""
							+ groupactions[child["cn"][0]]["target"] + "\"", file = outfile_script)

	# Merge group: Change gidNumber and msSFU30* attributes; description, name and
	# objectGUID of existing AD group stay the same.
	if actiontype == "merge":
		print("changetype: modify", file = outfile_ldif)
		write_replace(outfile_ldif, "msSFU30Name", target)
		write_replace(outfile_ldif, "msSFU30NisDomain", nis_domain)
		write_replace(outfile_ldif, "gidNumber", group["gidNumber"][0])

	# Migrate group: Add new group including all group properties
	elif actiontype == "migrate":
		print("changetype: add", file = outfile_ldif)
		print("cn: " + target, file = outfile_ldif)
		print("objectclass: top", file = outfile_ldif)
		print("objectclass: group", file = outfile_ldif)
		print("gidNumber: " + group["gidNumber"][0], file = outfile_ldif)
		print("sAMAccountName: " + target, file = outfile_ldif)
		print("msSFU30Name: " + target, file = outfile_ldif)
		print("msSFU30NisDomain: " + nis_domain, file = outfile_ldif)
		if "apple-group-realname" in group:
			print("description: " + group["apple-group-realname"][0], file=outfile_ldif)

		# Use `apple-generateduid` as `objectGUID` when migrating
		print("objectGUID: " + group["apple-generateduid"][0], file=outfile_ldif)
	else:
		print(group["cn"][0] + ": Invalid group action type: " + actiontype)
		quit()

	print(file = outfile_ldif)
	od_count += 1

# If -a / --amend-nis-props was specified (otherwise samba4_sysgroups is empty):
# Add gidNumber and NIS properties to all preexisting Samba4 groups, ignore groups that are marked for
# migration or merger in groups.json input file (group_is_manual is set in this case)
sysgroup_count = 0
for sysgroup_cn, sysgroup_rid in samba4_sysgroups.iteritems():
	group_is_manual = False

	for odgroup, groupprops in groupactions.iteritems():
		if groupprops["target"] == sysgroup_cn:
			group_is_manual = True
			continue

	if not group_is_manual:
		print("dn: CN=" + sysgroup_cn + ",CN=Users," + samba4_dc, file = outfile_ldif)
		print("changetype: modify", file = outfile_ldif)
		write_replace(outfile_ldif, "msSFU30Name", sysgroup_cn)
		write_replace(outfile_ldif, "msSFU30NisDomain", nis_domain)
		write_replace(outfile_ldif, "gidNumber", str(sysgroup_rid))
		print(file = outfile_ldif)
		sysgroup_count += 1

outfile_ldif.close()
outfile_script.close()
os.chmod(outfile_script_name, os.stat(outfile_script_name).st_mode | stat.S_IEXEC)

print("Extracted " + str(od_count) + " groups from Open Directory into " + outfile_ldif_name +  ".")
print("Amended " + str(sysgroup_count) + " groups from Samba4 with NIS properties.")
print("Copy this file to the samba4 server and import groups by executing")
print("# ldbmodify -H /var/lib/samba/private/sam.ldb " + outfile_ldif_name + " --relax")
print("Generated " + outfile_script_name + " for establishing group membership.")
print("Copy this script to the samba4 server and apply memberships by executing it.")

