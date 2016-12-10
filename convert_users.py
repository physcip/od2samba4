#!/usr/bin/env python2

# Convert Open Directory user database to LDIF for Samba4 import.
# It is not possible to just upload users to the Samba4 directory,
# since we want to keep objectGUIDs. Setting objectGUIDs of users
# is only allowed during provisioning with `ldbadd --relax` though.

from ConfigParser import RawConfigParser
from optparse import OptionParser
import xml.etree.ElementTree
import struct
import ldap
import ldif

# Parse command line options
parser = OptionParser()
parser.add_option("-n", "--new", action="store_true", default = False, help = "Only convert new users (users that are not in the samba4 directory)")
(cmdline_opts, args) = parser.parse_args()

# Parse configuration
config = RawConfigParser()
config.read("od2samba4.conf")

od_password = config.get("opendirectory", "password")
outfile_new_name = config.get("files", "newusers_ldif")
outfile_all_name = config.get("files", "users_ldif")
od_username = config.get("opendirectory", "username")
od_url = config.get("opendirectory", "url")
od_dc = config.get("opendirectory", "dc")
samba4_dc = config.get("samba4", "dc")
samba4_url = config.get("samba4", "url")
samba4_username = config.get("samba4", "username")
samba4_password = config.get("samba4", "password")
samba4_upn_realm = config.get("samba4", "upn_realm")
nis_domain = config.get("samba4", "nis_domain")

outfile_name = (outfile_new_name if cmdline_opts.new else outfile_all_name)

USERATTRIBUTES = [
	"cn",				# Common Name (First + Last Name)
	"uid",				# Username(s), multiple accounts possible!
	"givenName",			# First Name
	"sn",				# Last Name
	"apple-user-homeurl",		# Home Directory URL (on remote file server)
	"homeDirectory",		# Home Mountpoint (e.g. /home/jdoe)
	"loginShell",			# Login Shell, e.g. /bin/bash
	"gidNumber",			# Primary Group Number
	"uidNumber",			# UID Number
	"mail",				# E-Mail address, only first entry will be used
	"apple-generateduid",		# Becomes objectGUID in samba4
	"apple-user-mailattribute"	# XML format, forwarding address is extracted
]

# Use certificates only for encryption, not authentication (self-signed)
ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)

# Connect to Open Directory
print("Connecting to Open Directory server")
od = ldap.initialize(od_url)
od.simple_bind_s("uid=" + od_username + ",cn=users," + od_dc, od_password)

# Connect to Samba4
print("Connecting to Samba4 server")
samba = ldap.initialize(samba4_url)
samba.set_option(ldap.OPT_REFERRALS, 0)
samba.start_tls_s()
samba.simple_bind_s("cn=" + samba4_username + ",cn=Users," + samba4_dc, samba4_password)

# Retrieve list of users from OD and clean search results:
# - Search result is list of tuples (DN, attributes), extract attributes
# - Remove users that should not be migrated
od_results = od.search_s("cn=users," + od_dc, ldap.SCOPE_SUBTREE, "(objectclass=person)", USERATTRIBUTES)
users_all = [u[1] for u in od_results]
users_od = []
for user in users_all:
	if user["uid"][0] != "root" and user["uid"][0] != "_ldap_replicator" and not user["uid"][0].startswith("vpn_"):
		users_od.append(user)

print("Retrieved user list with " + str(len(users_od)) + " user entries from Open Directory")

# Retrieve list of groups from Samba4 - groups have to be migrated before running this script!
# RID (the last 4 bytes in little endian byte format, usually displayed as number after the last "-")
# of group's objectSid determines the primary group of the user. Build a dictionary that matches the
# group's gidNumber to the right RID. Open Directory contains the user's gidNumber attribute, so we
# can find a matching group RID for that. This RID will then be used as the user's primaryGroupID.
# The group's RID is also known as primaryGroupToken, though that attribute doesn't actually exist
# separately in Samba4.
print("Building gidNumber to primaryGroupToken Dictionary for Primary Group Membership")
samba_group_results = samba.search_s("cn=Users," + samba4_dc, ldap.SCOPE_SUBTREE, "(objectclass=group)", ["objectSid", "gidNumber"])
gid2rid = {}
for group in samba_group_results:
	if "gidNumber" in group[1]:
		gid2rid[group[1]["gidNumber"][0]] = struct.unpack("<i", group[1]["objectSid"][0][-4:])[0]

# If command line option --new is used, only add new users (UIDs that are not stored on the samba4 server)
# to output file. Connect to samba4 server to retrieve a list of registered UIDs.
uidlist = []
if cmdline_opts.new:
	print("Stripping userlist from already migrated users")
	samba_results = samba.search_s("cn=Users," + samba4_dc, ldap.SCOPE_SUBTREE, "(objectclass=person)", ["uid"])
	uidlist = [u[1]["uid"][0] for u in samba_results if "uid" in u[1]]
	users_od = [u for u in users_od if not (u["uid"][0] in uidlist)]
	print(str(len(users_od)) + " new user(s) found:")
	for u in users_od:
		print(u["uid"][0])


# Parse apple-user-mailattribute XML (an XML <dict>) looking for forwarding address
# Returns False if no forwarding Address was found
def extractForwardingAddress(xmlstring):
	root = xml.etree.ElementTree.fromstring(xmlstring)
	for key, child in enumerate(root):
		if child.text == "kAutoForwardValue" and not (root[key + 1].text is None):
			return root[key + 1].text.encode("utf-8")
	return False

# Generate LDIF for import into Samba4 via ldbadd
outfile = ldif.LDIFWriter(open(outfile_name, "wb"))
count = 0
for user in users_od:
	# Use OD's UID as CN and use OD's CN as displayName
	dn = "CN=" + user["uid"][0] + ",CN=Users," + samba4_dc
	user["displayName"] = [user["cn"][0]]
	user["cn"] = [user["uid"][0]]
	user["objectclass"] = ["top", "user", "organizationalPerson", "person", "posixAccount"]
	user["sAMAccountName"] = [user["uid"][0]]
	user["primaryGroupID"] = [str(gid2rid[user["gidNumber"][0]])]
	user["userPrincipalName"] = [user["uid"][0] + "@" + samba4_upn_realm]
	user["msSFU30Name"] = [user["uid"][0]]
	user["msSFU30NisDomain"] = [nis_domain]

	# Keep `apple-generateduid` from OD, rename to `objectGUID`
	user["objectGUID"] = [user["apple-generateduid"][0]]
	del user["apple-generateduid"]

	# If "mail" Attribute in OD is specified, use this for "mail" attribute in samba4.
	# Otherwise, try to extract forwarding mail address from "apple-user-mailattribute".
	if "mail" in user:
		user["mail"] = [user["mail"][0]]
	elif ("apple-user-mailattribute" in user) and extractForwardingAddress(user["apple-user-mailattribute"][0]):
		user["mail"] = [extractForwardingAddress(user["apple-user-mailattribute"][0])]
	if "apple-user-mailattribute" in user:
		del user["apple-user-mailattribute"]

	# Rename "homeDirectory" to "unixHomeDirectory"
	user["unixHomeDirectory"] = [user["homeDirectory"][0]]

	# Only keep first UID attribute, discard others
	user["uid"] = [user["uid"][0]]

	outfile.unparse(dn, user)
	count += 1

print("Extracted " + str(count) + " user account details into " + outfile_name +  ".")
print("Copy this file to the samba4 server and import users by executing")
print("# ldbadd -H /var/lib/samba/private/sam.ldb " + outfile_name + " --relax")
