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


def _bind_fails_server_down(self, who='', cred='', **kw):
    raise ldap.SERVER_DOWN('LDAP connection invalid')


def _bind_fails_server_down_failover(self, who='', cred='', **kw):
    # Raise a server down error unless the URI is 'ldap://GOOD'
    if self._uri == 'ldap://GOOD':
        self.connected = True
        self.who = who
        self.cred = cred
        return 1
    else:
        raise ldap.SERVER_DOWN('LDAP connection invalid')


def _bind_fails_timeout(self, who='', cred='', **kw):
    raise ldap.TIMEOUT('LDAP connection timeout')


def _bind_fails_timeout_failover(self, who='', cred='', **kw):
    # Raise a timeout error unless the URI is 'ldap://GOOD'
    if self._uri == 'ldap://GOOD':
        self.connected = True
        self.who = who
        self.cred = cred
        return 1
    else:
        raise ldap.TIMEOUT('LDAP connection timeout')


def _bind_fails_invalid_credentials(self, who='', cred='', **kw):
    raise ldap.INVALID_CREDENTIALS('LDAP connection invalid')


def _bind_fails_invalid_credentials_failover(self, who='', cred='', **kw):
    # Raise invalid credentials erorr unless the URI is 'ldap://GOOD'
    if self._uri == 'ldap://GOOD':
        self.connected = True
        self.who = who
        self.cred = cred
        return 1
    else:
        raise ldap.INVALID_CREDENTIALS('LDAP connection invalid')


def _start_tls_s(self):
    if self.start_tls_already_called_flag:
        raise ldap.LOCAL_ERROR
    else:
        self.start_tls_already_called_flag = True


class TestLDAPConnection(unittest.TestCase):

    def setUp(self):
        self.old = ldappool.StateConnector.simple_bind_s
        ldappool.StateConnector.simple_bind_s = _bind
        self.old_start_tls_s = ldappool.StateConnector.start_tls_s
        ldappool.StateConnector.start_tls_s = _start_tls_s
        ldappool.StateConnector.start_tls_already_called_flag = False

    def tearDown(self):
        ldappool.StateConnector.simple_bind_s = self.old
        ldappool.StateConnector.start_tls_s = self.old_start_tls_s

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

    def test_tls_connection(self):
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True,
                                        size=2, use_tls=True)
        with cm.connection():
            pass

    def test_simple_bind_fails(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding fails with an LDAPError
        ldappool.StateConnector.simple_bind_s = _bind_fails_server_down
        ldappool.StateConnector.unbind_s = _unbind
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass'):
                pass
        except ldap.SERVER_DOWN:
            pass
        else:
            raise AssertionError()

    def test_simple_bind_fails_failover(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding to any server other than 'ldap://GOOD' fails
        # with ldap.SERVER_DOWN
        ldappool.StateConnector.simple_bind_s = \
            _bind_fails_server_down_failover
        ldappool.StateConnector.unbind_s = _unbind
        uri = 'ldap://BAD,ldap://GOOD'
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass') as conn:
                # Ensure we failed over to the second URI
                self.assertTrue(conn.active)
                self.assertEqual(conn._uri, 'ldap://GOOD')
                pass
        except Exception:
            raise AssertionError()

    def test_simple_bind_fails_timeout(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding fails with ldap.TIMEOUT
        ldappool.StateConnector.simple_bind_s = _bind_fails_timeout
        ldappool.StateConnector.unbind_s = _unbind
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass'):
                pass
        except ldap.TIMEOUT:
            pass
        else:
            raise AssertionError()

    def test_simple_bind_fails_timeout_failover(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding to any server other than 'ldap://GOOD' fails
        # with ldap.TIMEOUT
        ldappool.StateConnector.simple_bind_s = _bind_fails_timeout_failover
        ldappool.StateConnector.unbind_s = _unbind
        uri = 'ldap://BAD,ldap://GOOD'
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass') as conn:
                # Ensure we failed over to the second URI
                self.assertTrue(conn.active)
                self.assertEqual(conn._uri, 'ldap://GOOD')
                pass
        except Exception:
            raise AssertionError()

    def test_simple_bind_fails_invalid_credentials(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding fails with an LDAPError
        ldappool.StateConnector.simple_bind_s = _bind_fails_invalid_credentials
        ldappool.StateConnector.unbind_s = _unbind
        uri = ''
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            with cm.connection('dn', 'pass'):
                pass
        except ldap.INVALID_CREDENTIALS:
            pass
        else:
            raise AssertionError()

    def test_simple_bind_fails_invalid_credentials_failover(self):
        unbinds = []

        def _unbind(self):
            unbinds.append(1)

        # the binding to any server other than 'ldap://GOOD' fails
        # with ldap.INVALID_CREDENTIALS
        ldappool.StateConnector.simple_bind_s = \
            _bind_fails_invalid_credentials_failover
        ldappool.StateConnector.unbind_s = _unbind
        uri = 'ldap://BAD,ldap://GOOD'
        dn = 'uid=adminuser,ou=logins,dc=mozilla'
        passwd = 'adminuser'
        cm = ldappool.ConnectionManager(uri, dn, passwd, use_pool=True, size=2)
        self.assertEqual(len(cm), 0)

        try:
            # We expect this to throw an INVALID_CREDENTIALS exception for the
            # first URI, as this is a hard-failure where we don't want failover
            # to occur to subsequent URIs.
            with cm.connection('dn', 'pass'):
                pass
        except ldap.INVALID_CREDENTIALS:
            pass
        else:
            raise AssertionError()
