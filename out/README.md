### Output Files
* `user_hashes.json`: All RC4 hashes that were extracted from the MIT Kerberos dump correlated to their UIDs. Created by `extract_hashes.py`. Required by `convert_hashes.py`.
* `addusers.ldif`: LDIF file with all user for import into samba4 AD DC. Can only be imported using `ldbadd` and only once after provisioning, since it force-sets objectGUIDs. Created by `convert_users.py`.
* `newusers.ldif`: LIDF file with new users (since last directory import from OD into samba4) for import into samba4 AD DC. Can only be imported using `ldbadd` and only once. Created by `convert_users.py --new`.
* `sethashes.ldif`: LDIF file that contains all user password hashes for import into samba4 AD DC. Accounts will only be enabled after this LDIF was imported. Can be imported using `ldbmodify` as many times as you wish. Created by `convert_hashes.py`.
