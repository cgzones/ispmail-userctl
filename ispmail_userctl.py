#!/usr/bin/python3 -EsWerror

# MIT License
#
# Copyright (c) 2019-2021 Christian Göttsche
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


######################
#                    #
# Configuration      #
#                    #
######################

# whether to use bcrypt passwords or sha512-crypt
USE_BCRYPT = False



import sys
import curses
import curses.ascii
from enum import Enum
from signal import signal, SIGWINCH
import os
import struct
from fcntl import ioctl
from termios import TIOCGWINSZ
import re


if not sys.stdout.isatty() or not sys.stdin.isatty():
    print('ISPMail userctl is based on curses and needs a real tty to work!')
    sys.exit(1)


NOTE = '\033[34;1m[*]\033[0m'
SUCC = '\033[32;1m[!]\033[0m'
WARN = '\033[33;1m[!]\033[0m'
ERR = '\033[31;1m[!]\033[0m'


try:
    import MySQLdb
except ImportError:
    print(ERR + ' No MySQLdb python module found!')
    print(NOTE + '     On Debian install python3-mysqldb')
    sys.exit(1)


if USE_BCRYPT:
    try:
        import bcrypt
    except ImportError:
        print(ERR + ' No bcrypt python module found!')
        print(NOTE + '     On Debian install python3-bcrypt')
        sys.exit(1)


def fmt_yellow(msg):
    return '\033[1;33m%s\033[0m' % msg


def format_quota(quota):
    if quota == 0:
        return 'unlimited'

    if quota < 1000:
        return '%s bytes' % quota

    quota /= 1000
    if quota < 1000:
        return '%s KB' % quota

    quota /= 1000
    if quota < 1000:
        return '%s MB' % quota

    quota /= 1000
    return '%s GB' % quota


def parse_quota(quota_raw):
    match = re.match(r'(\d+)\s*(\w+)?', quota_raw)
    if not match or not match[1]:
        return None

    amount = int(match[1])

    if not match[2]:
        return amount

    quantifier = match[2].casefold()

    if quantifier == 'kb':
        return 1000 * amount
    if quantifier == 'mb':
        return 1000 * 1000 * amount
    if quantifier == 'gb':
        return 1000 * 1000 * 1000 * amount

    return None


class DBDomain():
    def __init__(self, identifier, name):
        self.identifier = identifier
        self.name = name


class DBUser():
    def __init__(self, identifier, domain_id, email, quota):
        self.identifier = identifier
        self.domain_id = domain_id
        self.email = email
        self.quota = quota


class DBAlias():
    def __init__(self, identifier, domain_id, source, destination):
        self.identifier = identifier
        self.domain_id = domain_id
        self.source = source
        self.destination = destination


DB_CURSOR = None
DB_CONNECTION = None


def db_get_domains():
    domains = []
    DB_CURSOR.execute('SELECT id, name FROM virtual_domains ORDER BY name;')
    for row in DB_CURSOR.fetchall():
        domains.append(DBDomain(row[0], row[1]))
    return domains


def db_create_domain(name):
    DB_CURSOR.execute('INSERT INTO virtual_domains (name) VALUES (%s);', (name,))


def db_delete_domain(domain):
    DB_CURSOR.execute('DELETE FROM virtual_domains where id = %s;', (domain.identifier,))


def db_get_users(domain=None):
    users = []
    if domain:
        DB_CURSOR.execute('SELECT id, domain_id, email, quota FROM virtual_users WHERE domain_id = %s ORDER BY email;', (domain.identifier,))
    else:
        DB_CURSOR.execute('SELECT id, domain_id, email, quota FROM virtual_users ORDER BY email;')
    for row in DB_CURSOR.fetchall():
        users.append(DBUser(row[0], row[1], row[2], row[3]))
    return users


def db_create_user(domain, email, password, quota):
    if USE_BCRYPT:
        hashed_pw = bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt())
        DB_CURSOR.execute('INSERT INTO virtual_users (domain_id, email, password, quota) VALUES ( %s, %s, CONCAT("{BLF-CRYPT}", %s), %s);', (domain.identifier, email, hashed_pw, quota,))
    else:
        DB_CURSOR.execute('INSERT INTO virtual_users (domain_id, email, password, quota) VALUES ( %s, %s, CONCAT("{SHA512-CRYPT}", ENCRYPT (%s, CONCAT("$6$", SHA(RAND())))), %s);', (domain.identifier, email, password, quota,))


def db_update_password(user, password):
    if USE_BCRYPT:
        hashed_pw = bcrypt.hashpw(password.encode('UTF-8'), bcrypt.gensalt())
        DB_CURSOR.execute('UPDATE virtual_users SET password=CONCAT("{BLF-CRYPT}", %s) WHERE id = %s;', (hashed_pw, user.identifier,))
    else:
        DB_CURSOR.execute('UPDATE virtual_users SET password=CONCAT("{SHA512-CRYPT}", ENCRYPT (%s, CONCAT("$6$", SHA(RAND())))) WHERE id = %s;', (password, user.identifier,))


def db_update_quota(user, quota):
    DB_CURSOR.execute('UPDATE virtual_users SET quota=%s WHERE id = %s;', (quota, user.identifier,))


def db_delete_user(user):
    DB_CURSOR.execute('DELETE FROM virtual_users WHERE id = %s;', (user.identifier,))


def db_get_aliases(domain=None):
    aliases = []
    if domain:
        DB_CURSOR.execute('SELECT id, domain_id, source, destination FROM virtual_aliases WHERE domain_id = %s ORDER BY source, destination;', (domain.identifier,))
    else:
        DB_CURSOR.execute('SELECT id, domain_id, source, destination FROM virtual_aliases ORDER BY source, destination;')
    for row in DB_CURSOR.fetchall():
        aliases.append(DBAlias(row[0], row[1], row[2], row[3]))
    return aliases


def db_create_alias(domain, source, destination):
    DB_CURSOR.execute('INSERT INTO virtual_aliases (domain_id, source, destination) VALUES (%s, %s, %s);', (domain.identifier, source, destination,))


def db_delete_alias(alias):
    DB_CURSOR.execute('DELETE FROM virtual_aliases WHERE id = %s;', (alias.identifier,))


class Note():

    def __init__(self, parent, screen, title, top_title, text, continue_text='ok'):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.parent = parent
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.text = text
        self.continue_text = continue_text

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

    def draw(self):
        self.window.clear()

        self.window.addstr(1, 10, self.full_title, curses.A_BOLD)

        self.window.addstr(3, 1, self.text)

        self.window.addstr(5, 3, self.continue_text, curses.A_REVERSE)

        self.window.noutrefresh()

    def run(self):
        self.parent.add(self)

        while True:
            self.draw()
            curses.doupdate()

            key = self.window.getch()

            if key in [curses.KEY_ENTER, ord('\n'), ord('q'), ord('Q')]:
                break

        self.parent.remove(self)


class ConfirmResult(Enum):
    OPTA = 1
    OPTB = 2
    OPTNONE = 3


class Confirm():

    def __init__(self, parent, screen, title, top_title, text, opta_text, optb_text):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.parent = parent
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.text = text
        self.opta_text = opta_text
        self.optb_text = optb_text
        self.opta_active = True

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

    def draw(self):
        self.window.clear()

        self.window.addstr(1, 10, self.full_title, curses.A_BOLD)

        self.window.addstr(3, 1, self.text)

        if self.opta_active:
            self.window.addstr(5, 3, self.opta_text, curses.A_REVERSE)
            self.window.addstr(7, 3, self.optb_text, curses.A_NORMAL)
        else:
            self.window.addstr(5, 3, self.opta_text, curses.A_NORMAL)
            self.window.addstr(7, 3, self.optb_text, curses.A_REVERSE)

        self.window.noutrefresh()

    def run(self):
        self.parent.add(self)

        opt_return = ConfirmResult.OPTNONE

        while True:
            self.draw()
            curses.doupdate()

            key = self.window.getch()

            if key in [curses.KEY_ENTER, ord('\n')]:
                if self.opta_active:
                    opt_return = ConfirmResult.OPTA
                else:
                    opt_return = ConfirmResult.OPTB
                break

            elif key == curses.KEY_UP:
                self.opta_active = True

            elif key == curses.KEY_DOWN:
                self.opta_active = False

            elif key in [ord('q'), ord('Q')]:
                break

        self.parent.remove(self)

        return opt_return


class Select():

    def __init__(self, parent, screen, title, top_title, items):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.parent = parent
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.position = 0
        self.items = items
        self.items.append(('Return to %s' % top_title, None))

        self.pad = curses.newpad(len(self.items) + 4, screen.getmaxyx()[1] - 2)
        self.pad.bkgd(screen.getbkgd())

    def _navigate(self, num):
        self.position += num
        if self.position < 0:
            self.position = 0
        elif self.position >= len(self.items):
            self.position = len(self.items) - 1

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

    def draw(self):
        self.window.clear()
        self.window.noutrefresh()
        self.pad.clear()
        self.pad.addstr(1, 10, self.full_title, curses.A_BOLD)

        if len(self.items) > 1:
            for index, item in enumerate(self.items):
                mode = curses.A_REVERSE if index == self.position else curses.A_NORMAL
                offset = 1 if index == len(self.items) - 1 else 0

                msg = '%d. %s' % (index + 1, item[0])
                self.pad.addstr(index + 3 + offset, 1, msg, mode)
        else:
            self.pad.addstr(3, 1, 'No entry to select')
            self.pad.addstr(5, 1, self.items[0][0], curses.A_REVERSE)

        padpos = self.position
        if (self.window.getmaxyx()[0] - 5) > len(self.items) - padpos:
            padpos -= (self.window.getmaxyx()[0] - 5) - (len(self.items) - padpos)

        self.pad.refresh(padpos, 0, self.window.getbegyx()[0], self.window.getbegyx()[1], self.window.getbegyx()[0] + self.window.getmaxyx()[0] - 1, self.window.getbegyx()[1] + self.window.getmaxyx()[1] - 1)

    def run(self):
        self.parent.add(self)

        ret = None

        while True:
            self.draw()
            curses.doupdate()

            key = self.window.getch()

            if key in [curses.KEY_ENTER, ord('\n')]:
                if self.position != len(self.items) - 1:
                    ret = self.items[self.position][1]
                break

            elif key == curses.KEY_UP:
                self._navigate(-1)
            elif key == curses.KEY_DOWN:
                self._navigate(1)
            elif key == curses.KEY_NPAGE:
                self._navigate(15)
            elif key == curses.KEY_PPAGE:
                self._navigate(-15)

            elif key in [ord('q'), ord('Q')]:
                break

        self.parent.remove(self)

        return ret


class SingleInput():

    def __init__(self, parent, screen, title, top_title, text, input_visible):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.parent = parent
        self.top_title = top_title
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.text = text
        self.input_visible = input_visible
        self.input_string = ''
        self.input_active = True

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

    def draw(self):
        self.window.clear()

        self.window.addstr(1, 10, self.full_title, curses.A_BOLD)

        txt = self.input_string if self.input_visible else '*' * len(self.input_string)
        self.window.addstr(3, 1, self.text)

        self.window.addstr(5, 3, '> ')
        self.window.addstr(5, 5, txt, curses.color_pair(3))

        self.window.addstr(7, 1, 'Return to %s' % self.top_title, curses.A_NORMAL if self.input_active else curses.A_REVERSE)

        self.window.noutrefresh()

    def run(self):
        self.parent.add(self)

        while True:
            self.draw()
            curses.doupdate()

            if self.input_active:
                curses.curs_set(1)
            self.window.move(5, 5 + len(self.input_string))
            self.window.clrtoeol()
            key = self.window.getch()
            curses.curs_set(0)

            if key in [curses.KEY_ENTER, ord('\n')]:
                break

            elif key == curses.KEY_UP:
                self.input_active = True

            elif key == curses.KEY_DOWN:
                self.input_active = False

            elif self.input_active and curses.ascii.isgraph(key):
                self.input_string += chr(key)

            elif self.input_active and key in [curses.KEY_BACKSPACE, ord('\b')]:
                if self.input_string:
                    self.input_string = self.input_string[:-1]

        self.parent.remove(self)

        return self.input_string if self.input_active else None


class Info():

    def __init__(self, parent, screen, title, top_title, info):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.pad = curses.newpad(5 + info.count('\n'), screen.getmaxyx()[1] - 2)
        self.pad.bkgd(screen.getbkgd())

        self.parent = parent
        self.top_title = top_title
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.info = info
        self.pos = 0
        self.size = None

    def _navigate(self, num):
        self.pos += num
        if self.pos < 0:
            self.pos = 0
        if self.pos > self.size - self.window.getmaxyx()[0] + 4:
            self.pos = self.size - self.window.getmaxyx()[0] + 4

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

    def draw(self):
        self.window.clear()
        self.window.noutrefresh()
        self.pad.clear()
        self.pad.addstr(0, 9, self.full_title, curses.A_BOLD)
        self.pad.addstr(2, 0, self.info)
        self.pad.addstr('\n\nReturn to %s' % self.top_title, curses.A_REVERSE)
        self.pad.refresh(self.pos, 0, self.window.getbegyx()[0] + 1, self.window.getbegyx()[1] + 1, self.window.getbegyx()[0] + self.window.getmaxyx()[0] - 3, self.window.getbegyx()[1] + self.window.getmaxyx()[1] - 3)
        self.size = self.pad.getyx()[0]

    def run(self):
        self.parent.add(self)

        while True:
            self.draw()
            curses.doupdate()

            key = self.window.getch()

            if key in [curses.KEY_ENTER, ord('\n'), ord('q'), ord('Q')]:
                break
            elif key == curses.KEY_UP:
                self._navigate(-1)
            elif key == curses.KEY_DOWN:
                self._navigate(1)
            elif key == curses.KEY_NPAGE:
                self._navigate(15)
            elif key == curses.KEY_PPAGE:
                self._navigate(-15)

        self.parent.remove(self)


class Menu():

    def __init__(self, parent, screen, title, top_title, items, *args):
        self.window = screen.derwin(0, 0)
        self.window.keypad(1)

        self.parent = parent
        self.position = 0
        self.items = items
        if top_title:
            self.items.append(('Return to %s' % top_title, ))
        else:
            self.items.append(('Exit and Save Changes', ))
        self.full_title = '%s -> %s' % (top_title, title,) if top_title else title
        self.screen = screen
        self.args = args
        self.children = set()

    def _navigate(self, num):
        self.position += num
        if self.position < 0:
            self.position = 0
        elif self.position >= len(self.items):
            self.position = len(self.items) - 1

    def add(self, child):
        self.children.add(child)

    def remove(self, child):
        self.children.remove(child)

    def resize(self, lines, cols):
        self.window.resize(lines, cols)

        for child in self.children:
            child.resize(lines, cols)

    def draw(self):
        self.window.clear()

        self.window.addstr(1, 10, self.full_title, curses.A_BOLD)

        for index, item in enumerate(self.items):
            mode = curses.A_REVERSE if index == self.position else curses.A_NORMAL

            msg = '%d. %s' % (index + 1, item[0])
            self.window.addstr(index + 3, 1, msg, mode)

        self.window.noutrefresh()

        for child in self.children:
            child.draw()

    def run(self):
        self.parent.add(self)

        while True:
            self.draw()
            curses.doupdate()

            key = self.window.getch()

            if key in [curses.KEY_ENTER, ord('\n')]:
                if self.position == len(self.items) - 1:
                    break
                else:
                    do_exit = self.items[self.position][1](self, self.screen, self.full_title, *self.args)
                    if do_exit:
                        break

            elif key == curses.KEY_UP:
                self._navigate(-1)

            elif key == curses.KEY_DOWN:
                self._navigate(1)

            elif key in [ord('q'), ord('Q')]:
                break

        self.parent.remove(self)


def domain_overview_win(parent, window, top_title):
    domains = db_get_domains()
    text = 'Found %d domain(s):\n\n' % len(domains)
    for domain in domains:
        text += '\t%s\n' % domain.name

    handle = Info(parent, window, 'Domain Overview', top_title, text)
    handle.run()


def full_overview_win(parent, window, top_title):
    domains = db_get_domains()
    users = db_get_users()
    aliases = db_get_aliases()
    text = 'Found %d domain(s):\n\n' % len(domains)
    for domain in domains:
        text += '\t%s\n' % domain.name
    text += '\nFound %d user(s):\n\n' % len(users)
    for user in users:
        text += '\t%s  --  %s quota\n' % (user.email, format_quota(user.quota))
    text += '\nFound %d alias(es):\n\n' % len(aliases)
    for alias in aliases:
        foreign_msg = ' (foreign destination email)'
        for user in users:
            if user.email == alias.destination:
                foreign_msg = ' (internal destination email)'
                break

        text += '\t%s\n\t  -> %s%s\n' % (alias.source, alias.destination, foreign_msg)

    handle = Info(parent, window, 'Full Overview', top_title, text)
    handle.run()


def domain_add_win(parent, window, top_title):
    handle0 = SingleInput(parent, window, 'Add Domain', top_title, 'Enter the new domain name:', True)
    domain_name = handle0.run()
    if domain_name:
        if domain_name in [domain.name for domain in db_get_domains()]:
            handle1 = Note(parent, window, 'Add Domain Failed', top_title, 'Could not add domain \'%s\': domainname already exists.' % domain_name)
            handle1.run()
        else:
            db_create_domain(domain_name)
            handle1 = Note(parent, window, 'Add Domain Successful', top_title, 'Domain \'%s\' successfully added.' % domain_name)
            handle1.run()


def domain_selection_win(parent, window, top_title):
    handle0 = Select(parent, window, 'Select Domain to manage', top_title, [(domain.name, domain) for domain in db_get_domains()])
    domain = handle0.run()
    if domain:
        menu_items = [
            ('List users and aliases', domain_list_usersaliases_win),
            ('Change password of an user', domain_change_pw_win),
            ('Change quota of an user', domain_change_quota_win),
            ('Add user', domain_add_user_win),
            ('Add alias', domain_add_alias_win),
            ('Delete user', domain_delete_user_win),
            ('Delete alias', domain_delete_alias_win),
            ('Delete domain', domain_delete_confirm_win)
            ]
        handle1 = Menu(parent, window, 'Manage Domain \'%s\'' % domain.name, top_title, menu_items, domain)
        handle1.run()


def domain_list_usersaliases_win(parent, window, top_title, domain):
    users = db_get_users(domain)
    aliases = db_get_aliases(domain)
    text = '\nFound %d user(s):\n\n' % len(users)
    for user in users:
        text += '\t%s  --  %s quota\n' % (user.email, format_quota(user.quota))
    text += '\nFound %d alias(es):\n\n' % len(aliases)
    for alias in aliases:
        foreign_msg = ' (foreign destination email)'
        for user in users:
            if user.email == alias.destination:
                foreign_msg = ' (internal destination email)'
                break

        text += '\t%s\n\t  -> %s%s\n' % (alias.source, alias.destination, foreign_msg)

    handle = Info(parent, window, 'List of users and aliases', top_title, text)
    handle.run()


def domain_delete_user_win(parent, window, top_title, domain):
    handle0 = Select(parent, window, 'Select user to delete', top_title, [(user.email, user) for user in db_get_users(domain)])
    user = handle0.run()
    if user:
        handle1 = Confirm(parent, window, 'Delete User', top_title, 'Do you want to delete the user \'%s\'?' % user.email, 'no', 'yes')
        result = handle1.run()
        if result == ConfirmResult.OPTB:
            db_delete_user(user)


def domain_delete_alias_win(parent, window, top_title, domain):
    handle0 = Select(parent, window, 'Select alias to delete', top_title, [(alias.source, alias) for alias in db_get_aliases(domain)])
    alias = handle0.run()
    if alias:
        handle1 = Confirm(parent, window, 'Delete Alias', top_title, 'Do you want to delete the alias \'%s\' (to \'%s\')?' % (alias.source, alias.destination,), 'no', 'yes')
        result = handle1.run()
        if result == ConfirmResult.OPTB:
            db_delete_alias(alias)


def domain_change_pw_win(parent, window, top_title, domain):
    handle0 = Select(parent, window, 'Select user for password change', top_title, [(user.email, user) for user in db_get_users(domain)])
    user = handle0.run()
    if user:
        handle1 = SingleInput(parent, window, 'Password for user \'%s\' (1/2)' % user.email, top_title, 'Enter the new password:', False)
        pw1 = handle1.run()
        handle2 = SingleInput(parent, window, 'Password for user \'%s\' (2/2)' % user.email, top_title, 'Enter the new password again:', False)
        pw2 = handle2.run()

        if pw1 and pw1 == pw2:
            db_update_password(user, pw1)
            handle3 = Note(parent, window, 'Password Changed', top_title, 'Password for user \'%s\' successfully changed.' % user.email)
            handle3.run()
        else:
            handle3 = Note(parent, window, 'Password Changed Failed', top_title, 'Could not change password for user \'%s\': different new passwords.' % user.email)
            handle3.run()


def domain_change_quota_win(parent, window, top_title, domain):
    handle0 = Select(parent, window, 'Select user for quota change', top_title, [(user.email, user) for user in db_get_users(domain)])
    user = handle0.run()
    if user:
        handle1 = SingleInput(parent, window, 'Quota for user \'%s\'' % user.email, top_title, 'Enter the new quota amount:', True)
        quota_raw = handle1.run()
        if quota_raw:
            quota_parsed = parse_quota(quota_raw)
            if quota_parsed:
                db_update_quota(user, quota_parsed)
                handle2 = Note(parent, window, 'Quota Changed', top_title, 'Quota for user \'%s\' successfully changed.' % user.email)
                handle2.run()
            else:
                handle2 = Note(parent, window, 'Quota Changed Failed', top_title, 'Could not change quota for user \'%s\': invalid quota value.' % user.email)
                handle2.run()


def domain_add_user_win(parent, window, top_title, domain):
    handle0 = SingleInput(parent, window, 'Add User (1/4)', top_title, 'Enter the new username (the domain \'@%s\' will be appended):' % domain.name, True)
    user_name = handle0.run()
    if not user_name or user_name.find('@') != -1:
        handle1 = Note(parent, window, 'Add User Failed', top_title, 'Could not add new user: invalid username.')
        handle1.run()
        return

    if user_name + '@' + domain.name in [user.email for user in db_get_users(domain)]:
        handle5 = Note(parent, window, 'User Add Failed', top_title, 'Could not add user \'%s@%s\': username already exists.' % (user_name, domain.name,))
        handle5.run()
        return

    handle2 = SingleInput(parent, window, 'Add User (2/4)', top_title, 'Enter the new password:', False)
    pw1 = handle2.run()
    handle3 = SingleInput(parent, window, 'Add User (3/4)', top_title, 'Enter the new password again:', False)
    pw2 = handle3.run()

    if not pw1 or not pw2 or pw1 != pw2:
        handle4 = Note(parent, window, 'User Add Failed', top_title, 'Could not add new user \'%s@%s\': different new passwords.' % (user_name, domain.name,))
        handle4.run()
        return

    handle5 = SingleInput(parent, window, 'Add User (4/4)', top_title, 'Enter the new quota amount:', True)
    quota_raw = handle5.run()
    quota_parsed = parse_quota(quota_raw)
    if not quota_parsed:
        handle6 = Note(parent, window, 'User Add Failed', top_title, 'Could not add quota for user \'%s@%s\': invalid quota value.' % (user_name, domain.name,))
        handle6.run()
        return

    db_create_user(domain, user_name + '@%s' % domain.name, pw1, quota_parsed)
    handle7 = Note(parent, window, 'User Added Successful', top_title, 'User \'%s@%s\' successfully added.' % (user_name, domain.name,))
    handle7.run()


def domain_add_alias_win(parent, window, top_title, domain):
    handle0 = SingleInput(parent, window, 'Add Alias (1/2)', top_title, 'Enter the new alias source (the domain \'@%s\' will be appended):' % domain.name, True)
    source = handle0.run()
    if not source or source.find('@') != -1:
        handle1 = Note(parent, window, 'Add Alias Failed', top_title, 'Could not add new alias: invalid source.')
        handle1.run()
        return

    if source + '@' + domain.name in [alias.source for alias in db_get_aliases(domain)]:
        handle2 = Note(parent, window, 'Add Alias Failed', top_title, 'Could not add new alias: alias already exists.')
        handle2.run()
        return

    handle3 = SingleInput(parent, window, 'Add Alias (2/2)', top_title, 'Enter the new alias destination (supply the full address, with domain):', True)
    destination = handle3.run()
    if not destination or destination.find('@') == -1:
        handle4 = Note(parent, window, 'Add Alias Failed', top_title, 'Could not add new alias: invalid destination.')
        handle4.run()
        return

    db_create_alias(domain, source + '@%s' % domain.name, destination)
    handle5 = Note(parent, window, 'Alias Added', top_title, 'Alias \'%s@%s\' to \'%s\' successfully added.' % (source, domain.name, destination,))
    handle5.run()


def domain_delete_confirm_win(parent, window, top_title, domain):
    handle = Confirm(parent, window, 'Delete Domain', top_title, 'Do you want to delete the domain \'%s\'?' % domain.name, 'no', 'yes')
    result = handle.run()

    if result == ConfirmResult.OPTB:
        db_delete_domain(domain)
        return True

    return None


def discard_changes_win(parent, window, top_title):
    handle = Confirm(parent, window, 'Discard Changes', top_title, 'Do you want to discard all changes?', 'no', 'yes')
    if handle.run() == ConfirmResult.OPTB:
        DB_CONNECTION.rollback()


def save_changes_win(parent, window, top_title):
    handle = Confirm(parent, window, 'Save Changes', top_title, 'Do you want to save all changes?', 'no', 'yes')
    if handle.run() == ConfirmResult.OPTB:
        DB_CONNECTION.commit()


# From https://groups.google.com/forum/#!msg/comp.lang.python/CpUszNNXUQM/QADpl11Z-nAJ
def getheightwidth():
    """ getwidth() -> (int, int)

    Return the height and width of the console in characters """
    try:
        return int(os.environ["LINES"]), int(os.environ["COLUMNS"])
    except KeyError:
        height, width = struct.unpack("hhhh", ioctl(0, TIOCGWINSZ, "\000"*8))[0:2]
        if not height:
            return 25, 80
        return height, width


MAINAPP = None


def resize_handler(signum, frame):
    lines, cols = getheightwidth()
    curses.resizeterm(lines, cols)
    MAINAPP.resize(lines, cols)
    MAINAPP.draw()


class MainApp():

    header_size = 5
    header_text = 'ISPMail userctl'
    footer_size = 1
    main_margin = 2

    def __init__(self, screen):
        lines, cols = screen.getmaxyx()
        self.header_win = screen.derwin(self.header_size, cols, 0, 0)
        self.working_win = screen.derwin(lines - self.header_size - self.footer_size, cols - 2 * self.main_margin, self.header_size, self.main_margin)
        self.working_win.bkgd(curses.color_pair(2))
        self.footer_win = screen.derwin(self.footer_size, cols, lines - self.footer_size, 0)
        self.children = set()

        main_menu_items = [
            ('List domains', domain_overview_win),
            ('List everything', full_overview_win),
            ('Add domain', domain_add_win),
            ('Manage domain', domain_selection_win),
            ('Save changes', save_changes_win),
            ('Discard changes', discard_changes_win),
            ]
        self.main_menu = Menu(self, self.working_win, 'Overview', None, main_menu_items)

    def add(self, child):
        self.children.add(child)

    def remove(self, child):
        self.children.remove(child)

    def resize(self, lines, cols):
        self.header_win.resize(self.header_size, cols)
        self.header_win.mvwin(0, 0)

        self.working_win.resize(lines - self.header_size - self.footer_size, cols - 2 * self.main_margin)
        self.working_win.mvwin(self.header_size, self.main_margin)

        self.footer_win.resize(self.footer_size, cols)
        self.footer_win.mvwin(lines - self.footer_size, 0)

        for child in self.children:
            child.resize(lines - self.header_size - self.footer_size, cols - 2 * self.main_margin)

    def draw(self):
        self.header_win.clear()

        self.header_win.addstr(int(self.header_size / 2), int(self.header_win.getmaxyx()[1] / 2) - int(len(self.header_text) / 2), self.header_text, curses.color_pair(1) | curses.A_BOLD)

        self.header_win.noutrefresh()

        self.working_win.clear()
        self.working_win.noutrefresh()

        self.footer_win.clear()
        self.footer_win.addstr(0, 7, 'Usage: (q) to return/quit, UP/DOWN to navigate')
        self.footer_win.noutrefresh()

        for child in self.children:
            child.draw()

    def run(self):
        self.draw()
        self.main_menu.run()


def main_app(screen):
    curses.curs_set(0)
    curses.start_color()

    curses.init_pair(1, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(3, curses.COLOR_BLACK, curses.COLOR_GREEN)

    global MAINAPP
    MAINAPP = MainApp(screen)

    signal(SIGWINCH, resize_handler)

    MAINAPP.run()


def main():
    print(NOTE + ' # ISPMail userctl')

    lines, cols = getheightwidth()
    if lines < 25 or cols < 80:
        print(WARN + '   small terminal detected (%d x %d)' % (lines, cols, ))
        print(WARN + '   recommend minimum is (25 x 80)')
        print(WARN + '   app might be unstable')

    global DB_CURSOR
    global DB_CONNECTION

    try:
        DB_CONNECTION = MySQLdb.connect(
            host='localhost',
            user='root',
            # password='',
            db='mailserver',
            charset='utf8mb4')

        DB_CURSOR = DB_CONNECTION.cursor()

        curses.wrapper(main_app)

    except KeyboardInterrupt:
        if DB_CURSOR:
            DB_CURSOR.close()
        if DB_CONNECTION:
            DB_CONNECTION.rollback()
            DB_CONNECTION.close()

        print(WARN + fmt_yellow(' Unsaved changes are lost!'))
        sys.exit(1)

    except MySQLdb.Error as err:
        if DB_CURSOR:
            DB_CURSOR.close()
        if DB_CONNECTION:
            DB_CONNECTION.rollback()
            DB_CONNECTION.close()

        print(ERR + ' MySQLdb error %d: %s' % (err.args[0], err.args[1],))
        print(WARN + fmt_yellow(' Unsaved changes are lost!'))
        raise

    except:
        if DB_CURSOR:
            DB_CURSOR.close()
        if DB_CONNECTION:
            DB_CONNECTION.rollback()
            DB_CONNECTION.close()

        print(ERR + ' Unexpected exception:', sys.exc_info()[1])
        print(WARN + fmt_yellow(' Unsaved changes are lost!'))
        raise

    DB_CURSOR.close()
    DB_CONNECTION.commit()
    DB_CONNECTION.close()

    print(SUCC + ' Bye..')


if __name__ == '__main__':
    sys.exit(main())
