#!/usr/bin/env python2.7

# This script converts hashes as can be obtained from a MIT Kerberos / Heimdal dump to the supplementalCredentials
# binary blob used in Active Directory / Samba4.
# Using heimdal, you can print out these hashes to the console using:
# hprop --database=dump.mit --source=mit-dump --decrypt --master-key=kdc_master_key --stdout | hpropd -n --print
#
# Usage:
# kerberos2supplementalCredentials.py --salt SALT [--type1 HASH1] [--type3 HASH3] [--type17 HASH17] [--type18 HASH18] [--base64]
# Where hashes 1, 3, 17, 18 correspond to the kerberos enctypes des-cbc-crc, des-cbc-md5, aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96.
# Hashes 1, 3, 17, 18 are optional and can be omitted if you don't want to include that specific hash in your supplementalCredentials blob.
# If --base64 is specified, output will be in base64 format (ready for LDIF import), otherwise binary output is generated.
#
# If you don't have any salt data, you propably want to try using the "normal" kerberos salt, which is defined as the concatenation
# [REALM] + [PRINCIPAL]. So if the domain is "EXAMPLE.ORG" and the principal is "Administrator", the salt would be "EXAMPLE.ORGAdministrator".
# See pr_to_salt.c in MIT Kerberos or krb5_get_pw_salt(...) in salt.c in Heimdal for more information / source.
# The result supplementalCredentials blob will be printed to stdout.
#
# This script does NOT encode the WDigest credentials, since those hashes cannot be obtained from Kerberos.
# This script does NOT support random / different salts for the different hashes.
#
# Note about the supplementalCredentialsPackage's reserved property:
# This property is defined here: https://msdn.microsoft.com/en-us/library/cc245501.aspx and will be ignored, but is set to 1 or 2 according to
# https://msdn.microsoft.com/en-us/library/cc245831.aspx#Appendix_A_22; Samba sets this as 1 for non-"Package" supplementalCredentialsPackages
# and to 2 for the "Package" supplementalCredentialsPackage, see source4/dsdb/samdb/ldb_modules/password_hash.c; that's the behaviour we emulate
# here as well

import argparse
import string
import binascii
import sys
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import drsblobs

# Mind that the order of this list matters!
# The order in the "Primary:Kerberos-Newer-Keys" list must be: type18, type17, type3, type1
# The order in the "Primary:Kerberos" list must be: type3, type1
# Therefore, this list has to be sorted by type numbers in descending order.
hashes = [
	{ "arg" : "type18", "name" : "aes256-cts-hmac-sha1-96", "type" : 18, "length" : 32, "ctr3" : False },
	{ "arg" : "type17", "name" : "aes128-cts-hmac-sha1-96", "type" : 17, "length" : 16, "ctr3" : False },
	{ "arg" : "type3", "name" : "des-cbc-md5", "type" : 3, "length" : 8, "ctr3" : True },
	{ "arg" : "type1", "name" : "des-cbc-crc", "type" : 1, "length" : 8, "ctr3" : True }
]

# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("salt", help="Salt string that the hashes were created with")
parser.add_argument("--base64", help="Output supplementalCredentials blob in base64 format", action="store_true")

for props in hashes:
	parser.add_argument("--" + props["arg"], help = "Enctype " + str(props["type"]) + " (" + props["name"] + ") hash in HEX format")

args = parser.parse_args()

# Make sure parameters are valid (check lengths, check if strings are hexadecimal)
hash_specified = False
for props in hashes:
	if vars(args)[props["arg"]]:
		hash_specified = True
		assert len(binascii.unhexlify(vars(args)[props["arg"]])) == props["length"]
		if (not all(d in string.hexdigits for d in vars(args)[props["arg"]])):
			sys.exit("Error: Hashes must be in hexadecimal format")

if not hash_specified:
	sys.exit("Error: At least one hash must be specified. Nothing to do.")

salt_blob = drsblobs.package_PrimaryKerberosString()
salt_blob.string = args.salt

# Dictionary containing property name (string) and content (a supplementalCredentialsPackage)
properties = {}

# Store type 1, 3, 17, 18 hashes in Primary:Kerberos-Newer-Keys
# https://msdn.microsoft.com/en-us/library/cc941808.aspx
# "ctr4" because this is a revision 4 key container
newer_keys_list = []
for props in hashes:
	if vars(args)[props["arg"]]:
		key = drsblobs.package_PrimaryKerberosKey4()
		key.keytype = props["type"]
		key.value = binascii.unhexlify(vars(args)[props["arg"]])
		key.value_len = props["length"]
		newer_keys_list.append(key)

newer_keys_ctr = drsblobs.package_PrimaryKerberosCtr4()
newer_keys_ctr.num_keys = len(newer_keys_list)
newer_keys_ctr.salt = salt_blob
newer_keys_ctr.keys = newer_keys_list

newer_keys_blob_unpacked = drsblobs.package_PrimaryKerberosBlob()
newer_keys_blob_unpacked.version = 4
newer_keys_blob_unpacked.ctr = newer_keys_ctr
newer_keys_blob = ndr_pack(newer_keys_blob_unpacked)

newer_keys_package = drsblobs.supplementalCredentialsPackage()
newer_keys_package_hex = binascii.hexlify(newer_keys_blob).upper()
newer_keys_package.data = newer_keys_package_hex
newer_keys_package.data_len = len(newer_keys_package.data)
newer_keys_package.name = "Primary:Kerberos-Newer-Keys"
newer_keys_package.name_len = len(newer_keys_package.name)
newer_keys_package.reserved = 1 # see note about this property above

properties["Kerberos-Newer-Keys"] = newer_keys_package

# Store type 1 and 3 hashes in Primary:Kerberos
# https://msdn.microsoft.com/en-us/library/cc245503.aspx
# "ctr3" because this is a revision 3 key container
normal_keys_list = []
for props in hashes:
	if vars(args)[props["arg"]] and props["ctr3"]:
		key = drsblobs.package_PrimaryKerberosKey3()
		key.keytype = props["type"]
		key.value = binascii.unhexlify(vars(args)[props["arg"]])
		key.value_len = props["length"]
		normal_keys_list.append(key)

# It is possible to only specify keys 17, 18
# Then no need to generate the old format entry
if (len(normal_keys_list) > 0):
	normal_keys_ctr = drsblobs.package_PrimaryKerberosCtr3()
	normal_keys_ctr.num_keys = len(normal_keys_list)
	normal_keys_ctr.salt = salt_blob
	normal_keys_ctr.keys = normal_keys_list

	normal_keys_blob_unpacked = drsblobs.package_PrimaryKerberosBlob()
	normal_keys_blob_unpacked.version = 3
	normal_keys_blob_unpacked.ctr = normal_keys_ctr
	normal_keys_blob = ndr_pack(normal_keys_blob_unpacked)

	normal_keys_package = drsblobs.supplementalCredentialsPackage()
	normal_keys_package_hex = binascii.hexlify(normal_keys_blob).upper()
	normal_keys_package.data = normal_keys_package_hex
	normal_keys_package.data_len = len(normal_keys_package.data)
	normal_keys_package.name = "Primary:Kerberos"
	normal_keys_package.name_len = len(normal_keys_package.name)
	normal_keys_package.reserved = 1 # see note about this property above

	properties["Kerberos"] = normal_keys_package

# Build packages property Blob
# https://msdn.microsoft.com/en-us/library/cc245678.aspx
propertynames = []
propertydata = []
for name, package in properties.iteritems():
	propertynames.append(name)
	propertydata.append(package)

packages_listblob = "\0".join(propertynames).encode("utf-16le")

packages_blob = drsblobs.supplementalCredentialsPackage()
packages_blob.name = "Packages"
packages_blob.name_len = len(packages_blob.name)
packages_blob.data = binascii.hexlify(packages_listblob).upper()
packages_blob.data_len = len(packages_blob.data)
packages_blob.reserved = 2 # see note about this property above

# Build supplementalCredentials blob
# https://msdn.microsoft.com/en-us/library/cc245500.aspx
supcred_sections = [packages_blob]
supcred_sections.extend(propertydata)

supcred_subblock = drsblobs.supplementalCredentialsSubBlob()
supcred_subblock.packages = supcred_sections
supcred_subblock.num_packages = len(supcred_sections)
supcred_subblock.prefix = drsblobs.SUPPLEMENTAL_CREDENTIALS_PREFIX
supcred_subblock.signature = drsblobs.SUPPLEMENTAL_CREDENTIALS_SIGNATURE

supcred_blob_unpacked = drsblobs.supplementalCredentialsBlob()
supcred_blob_unpacked.sub = supcred_subblock
supcred_blob = ndr_pack(supcred_blob_unpacked)

if args.base64:
	print(binascii.b2a_base64(supcred_blob))
else:
	print(supcred_blob)
