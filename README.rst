ldappool
========

A simple connector pool for python-ldap.

The pool keeps LDAP connectors alive and let you reuse them,
drastically reducing the time spent to initiate a ldap connection.

The pool has useful features like:

- transparent reconnection on failures or server restarts
- configurable pool size and connectors timeouts
- configurable max lifetime for connectors
- a context manager to simplify acquiring and releasing a connector

**You need python-ldap in order to use this library**

Quickstart
::::::::::

To work with the pool, you just need to create it, then use it as a
context manager with the *connection* method::

    from ldappool import ConnectionManager

    cm = ConnectionManager('ldap://localhost')

    with cm.connection('uid=adminuser,ou=logins,dc=mozilla', 'password') as conn:
        .. do something with conn ..


The connector returned by *connection* is a LDAPObject, that's binded to the
server. See https://pypi.org/project/python-ldap/ for details on how to use a connector.

It is possible to check the state of the pool by representing the pool as a string::

    from ldappool import ConnectionManager

    cm = ConnectionManager('ldap://localhost', size=2)

    .. do something with cm ..

    print(cm)

This will result in output similar to this table::

    +--------------+-----------+----------+------------------+--------------------+------------------------------+
    | Slot (2 max) | Connected |  Active  |       URI        | Lifetime (600 max) |           Bind DN            |
    +--------------+-----------+----------+------------------+--------------------+------------------------------+
    |      1       | connected | inactive | ldap://localhost |  0.00496101379395  | uid=tuser,dc=example,dc=test |
    |      2       | connected | inactive | ldap://localhost |  0.00532603263855  | uid=tuser,dc=example,dc=test |
    +--------------+-----------+----------+------------------+--------------------+------------------------------+


ConnectionManager options
:::::::::::::::::::::::::

Here are the options you can use when instanciating the pool:

- **uri**: ldap server uri **[mandatory]**
- **bind**: default bind that will be used to bind a connector.
  **default: None**
- **passwd**: default password that will be used to bind a connector.
  **default: None**
- **size**: pool size. **default: 10**
- **retry_max**: number of attempts when a server is down. **default: 3**
- **retry_delay**: delay in seconds before a retry. **default: .1**
- **use_tls**: activate TLS when connecting. **default: False**
- **timeout**: connector timeout. **default: -1**
- **use_pool**: activates the pool. If False, will recreate a connector
  each time. **default: True**

The **uri** option will accept a comma or whitespace separated list of LDAP
server URIs to allow for failover behavior when connection errors are
encountered.  Connections will be attempted against the servers in order,
with **retry_max** attempts per URI before failing over to the next server.

The **connection** method takes two options:

- **bind**: bind used to connect. If None, uses the pool default's.
  **default: None**
- **passwd**: password used to connect. If None, uses the pool default's.
  **default: None**
