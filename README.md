# ispmail-userctl
Python script using ncurses to manage domains, users and aliases of an ISP-style mail server.

___

This script is intended to work on a mail sever installation from https://workaround.org/ispmail by Christoph Haas.
It assumes the database tables to be formatted exactly as described in https://workaround.org/ispmail/buster/prepare-the-database/.

By default passwords are hashed with SHA512; one can change the script to use BCRYPT.

## Dependencies
- python3
- MySQLdb python module (`python3-mysqldb` on Debian)
- (Optional) bcrypt python module (`python3-bcrypt` on Debian)

## License
[MIT License](https://opensource.org/licenses/MIT)
