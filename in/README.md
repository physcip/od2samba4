### Input Files
* `kdc_dump.mit`: MIT Kerberos dump from Open Directory, can be generated using `kdb5_util dump -b7 kdc_dump.mit`. od2samba4 will extract the password hashes from this dump. Required by `extract_hashes.py`.
* `kdc_master_key`: MIT Kerberos Master Key from Open Directory. File location is determined by `key_stash_file` property in `/var/db/krb5kdc/kdc.conf`. Required by `extract_hashes.py`.
