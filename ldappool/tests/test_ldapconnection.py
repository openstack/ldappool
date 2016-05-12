# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is Sync Server
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Tarek Ziade (tarek@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
import unittest

import ldap

import ldappool


def _bind(self, who='', cred='', **kw):
    self.connected = True
    self.who = who
    self.cred = cred
    return 1


def _bind_fails(self, who='', cred='', **kw):
    raise ldap.LDAPError('LDAP connection invalid')


def _bind_fails2(self, who='', cred='', **kw):
    raise ldap.SERVER_DOWN('LDAP connection invalid')


class TestLDAPConnection(unittest.TestCase):

    def setUp(self):
        self.old = ldappool.StateConnector.simple_bind_s
        ldappool.StateConnector.simple_bind_s = _bind

    def tearDown(self):
        ldappool.StateConnector.simple_bind_s = self.old

    def test_connection(self):
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        with cm.connection('dn', 'pass'):
            self.assertEqual(len(cm), 1)

            # if we ask a new one the pool will grow
            with cm.connection('dn', 'pass'):
                self.assertEqual(len(cm), 2)

                # every connector is marked active
                self.assertTrue(cm._pool[0].active)
                self.assertTrue(cm._pool[1].active)

                # if we ask a new one the pool is full
                try:
                    with cm.connection('dn', 'pass'):
                        pass
                except ldappool.MaxConnectionReachedError:
                    pass
                else:
                    raise AssertionError()

            # down to one active
            self.assertFalse(cm._pool[1].active)
            self.assertTrue(cm._pool[0].active)

            # if we ask a new one the pool is full
            # but we get the inactive one
            with cm.connection('dn', 'pass'):
                self.assertEqual(len(cm), 2)

            self.assertFalse(cm._pool[1].active)
            self.assertTrue(cm._pool[0].active)

            # if we ask a new one the pool is full
            # but we get the inactive one, and rebind it
            with cm.connection('dn2', 'pass'):
                self.assertEqual(len(cm), 2)

        # the pool is still 2
        self.assertEqual(len(cm), 2)

        # every connector is marked inactive
        self.assertFalse(cm._pool[0].active)
        self.assertFalse(cm._pool[1].active)

    def test_simple_bind_fails(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding fails with an LDAPError
        ldappool.StateConnector.simple_bind_s = _bind_fails2
        ldappool.StateConnector.unbind_s = _unbind
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass'):
                pass
        except ldappool.BackendError:
            pass
        else:
            raise AssertionError()
