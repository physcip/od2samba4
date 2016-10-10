# Open Directory to Samba4 Migration tools
od2samba4 is a set of tools that simplify migrating users (including passwords) and groups from Apple Open Directory to Samba4 Active Directory Domain Controller. od2samba4 preserves `apple-generateduid`s of users and groups, which will become `objectGUID`s in Samba4. RC4 Password hashes are converted to a Samba4-compatible format using [Heimdal](https://www.h5l.org/). After migration and before making the final switch to Samba4, Open Directory and Samba4 can be used simultaneously, while new users and password updates are automatically synchronized.

## Architecture
Apart from the `sync.sh` script, od2samba4 does *not* modify data on the Samba4 server. Instead, the python scripts only generate outputs (LDIF files) that have to be manually imported into the LDB database. This way, od2samba4 can modify normally immutable attributes like objectGUIDs and password hashes without you having to worry about accidentally changing entries in the Active Directory. On the downside, this means that after messing up the Samba4 database (e.g. by deleting a user that is still present in Open Directory) there is no way to recover other than re-provisioning Samba4.

Apart from the sync utilities, od2samba4 does not have to be used on the Samba4 server itself. Output files can just as well be generated on any system and copied over to the Samba4 server.

## Usage
od2samba4 has been tested with **Debian 8**. This guide only covers Debian-specific packages and commands, please adapt them to your linux distribution accordingly.

### Step 1 - Install Samba4 and Utilities
On the Samba4 server, install Samba4 and some dependencies:
```bash
apt install samba smbclient winbind krb5-user
```

On the system running od2samba4 (which can be the Samba4 server, but doesn't have to be), install heimdal and python-ldap for python2. Also, immediately disable the heimdal server, which would otherwise interfere with samba.
```bash
apt install heimdal-clients heimdal-kdc python-ldap
systemctl disable heimdal-kdc
systemctl stop heimdal-kdc
```

### Step 2 - Samba4 Provisioning and Setup
Follow the [official guide for provisioning a Samba4 Domain Controller](https://wiki.samba.org/index.php/Setup_a_Samba_Active_Directory_Domain_Controller). Make sure to use `--use-rfc2307` when provisioning and configure `/etc/resolv.conf` according to the official guide to make sure the hostname of the Open Directory server can be resolved or manually add an entry to `/etc/hosts`. Enable the Samba4 Active Directory Domain Controller (Debian: should happen automatically, or use `systemctl start samba-ad-dc`). Mind that from now on, the Samba4 server has to be running for internet access (since it acts as the DNS server).

### Step 3 - Install Schema Extensions
od2samba4 migrates the Open Directory attribute `apple-user-homeurl` to Samba4. Since that is not a default Active Directory attribute, it has to be manually added by installing schema extensions.

The following commands install the schema extensions from the `extensions` folder. Samba4 must not be running while the schema is modified. 
```bash
systemctl stop samba-ad-dc
ldbmodify -H /var/lib/samba/private/sam.ldb extensions/apple-user-homeurl.ldif --option="dsdb:schema update allowed"=true
ldbmodify -H /var/lib/samba/private/sam.ldb extensions/apple-user-homeurl-contain.ldif --option="dsdb:schema update allowed"=true
systemctl start samba-ad-dc
```

### Step 4 - Modify Password Settings
od2samba4 will set all `pwdLastSet` fields in the Active Directory to the time `convert_hashes.py` is executed. If you don't want all your passwords to suddenly expire at the same time, disable maximum / minimum password age:
```bash
samba-tool domain passwordsettings set --min-pwd-age=0
samba-tool domain passwordsettings set --max-pwd-age=0
```

### Step 5 - Initial Migration of Users, Passwords and Groups
#### od2samba4.conf Settings
od2samba4 needs information on how to contact both Open Directory and Samba4 as well as information on where to find and store files. Samba4 server contact information is only used to read the directory (e.g. to find out which users haven't been migrated yet), od2samba4 won't write to the Samba4 directory. Configure od2samba4 by creating a copy of `od2samba4.conf.example` called `od2samba4.conf` and enter the following settings:

* `[files]` section:
	* For details on input and output files, see `in/README.md` and `out/README.md` respectively
	* `heimdal_path`: Path to `hprop` and `hpropd` executables, which are included in heimdal. Propably `/usr/sbin`.
* `[opendirectory]` section:
	* `dc`: Domain component of the OD server
	* `url`: Where to reach your OD server via LDAP protocol
	* `username`: Username for OD server
	* `password`: Password for given username on OD server
	* `host`, `sshuser`, `sshpass`: only required for automatic synchronization, see `sync/README.md`
* `[samba4]` section:
	* `dc`: Domain component of the Samba4 server
	* `url`: Where to reach your Samba4 server via LDAP (or LDAPS) protocol
	* `username`: Username for AD server
	* `password`: Password for AD server
	* `group_nis_domain`: `msSFU30NisDomain` attribute of groups, usually the lowercase domain name

#### Migrate Users
`convert_users.py` will generate an LDIF file with all Open Directory users for Samba4 import. You may also choose to only extract users that have not already been migrated ("new users") using `convert_users.py --new`.

Users can then be imported using
```bash
ldbadd -H /var/lib/samba/private/sam.ldb <user ldif file> --relax
```
The `--relax` option makes sure, LDB accepts the LDIF despite it specifying objectGUIDs, which can't normally be written directly.

#### Migrate Password Hashes
Obtain `mit_dump` and `master_key` files as described in `in/README.md`. Extract hashes using `extract_hashes.py`. This will generate the `hashes` file which contains all arcfour-hmac-md5 (RC4) hashes assigned to usernames in a JSON format. This file is for internal usage in od2samba4 only.

Convert hashes to LDIF for Samba4 import using `convert_hashes.py`. This script will also make sure to only include those hashes in the LDIF, whose corresponding users are known by Samba4. The LDIF generated by `convert_hashes.py` also sets `pwdLastSet` to the current system time and enables the user account.

Import password hashes into Samba4 using
```bash
ldbmodify <hashes ldif file> -H /var/lib/samba/private/sam.ldb --controls=local_oid:1.3.6.1.4.1.7165.4.3.12:0
```
The control (`1.3.6.1.4.1.7165.4.3.12 = DSDB_CONTROL_BYPASS_PASSWORD_HASH_OID`, which was intended to be used for Samba3 import) will make sure, to override a check that prevents ldbmodify to directly change password hashes.

#### Migrate Groups
`convert_groups.py` will generate an LDIF file with all Open Directory groups for Samba4 import. Group migration is only meant to be done once (there is no option to only migrate new groups).

Groups can then be imported using
```bash
ldbadd -H /var/lib/samba/private/sam.ldb <group ldif file> --relax
```

Additionally, a script that establishes group membership is created. By executing this script, `member` and `memberUid` attributes are added to the group and `memberOf` attributes are added to group members.

### Step 6 - Simultaneous OD and Samba4 Operation with Automatic Import
If you want to test Samba4 for some time before making the final switch while synchronizing password changes and new users from OD over to the Samba4 server, see `sync/README.md` for information on how to accomplish that.
