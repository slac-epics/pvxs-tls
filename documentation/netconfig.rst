.. _netconfig:

PVA Network Configuration
=========================

PVA network configuration is conventionally expressed through environment variables.
New API users are suggested to start with `pvxs::client::Context::fromEnv`
or `pvxs::server::Config::fromEnv`.

.. _environ:

Environment variables
---------------------

This table lists all of the ``$EPICS_PVA*`` environment variables understood by PVXS.
See Client :ref:`clientconf` and Server :ref:`serverconf` for detailed explanations.

Many variables come in pairs of ``$EPICS_PVA_*`` and ``$EPICS_PVAS_*``.
A Client will look at only ``$EPICS_PVA_*``.
A server will prefer ``$EPICS_PVAS_*`` if set,
or fallback to use the associated ``$EPICS_PVA_*`` if set.

+----------------------------------+--------+--------+
|             Variable             | Client | Server |
+==================================+========+========+
|       EPICS_PVA_ADDR_LIST        |   x    |   x    |
+----------------------------------+--------+--------+
|   EPICS_PVAS_BEACON_ADDR_LIST    |        |   x    |
+----------------------------------+--------+--------+
|     EPICS_PVA_AUTO_ADDR_LIST     |   x    |   x    |
+----------------------------------+--------+--------+
| EPICS_PVAS_AUTO_BEACON_ADDR_LIST |        |   x    |
+----------------------------------+--------+--------+
|    EPICS_PVAS_INTF_ADDR_LIST     |        |   x    |
+----------------------------------+--------+--------+
|      EPICS_PVA_SERVER_PORT       |   x    |   x    |
+----------------------------------+--------+--------+
|      EPICS_PVAS_SERVER_PORT      |        |   x    |
+----------------------------------+--------+--------+
|     EPICS_PVA_BROADCAST_PORT     |   x    |   x    |
+----------------------------------+--------+--------+
|    EPICS_PVAS_BROADCAST_PORT     |        |   x    |
+----------------------------------+--------+--------+
|   EPICS_PVAS_IGNORE_ADDR_LIST    |        |   x    |
+----------------------------------+--------+--------+
|        EPICS_PVA_CONN_TMO        |   x    |   x    |
+----------------------------------+--------+--------+
|      EPICS_PVA_NAME_SERVERS      |   x    |        |
+----------------------------------+--------+--------+


.. _tlsoptions:

TLS Options
-----------

A server's TLS behavior can be tuned through the ``$EPICS_PVAS_TLS_OPTIONS`` environment
variable (clients use ``$EPICS_PVA_TLS_OPTIONS``).  Its value is a space-separated list of
tokens.  Unknown tokens are logged with a warning and ignored, so configuration files
containing newer tokens remain safe to read with older PVXS binaries.

The ``no_tcp`` token disables the plaintext PVAccess TCP listener entirely.  When it is
set, the server only accepts TLS connections: it does not bind the plaintext server port,
its SEARCH replies and beacons advertise only the TLS endpoint, and it does not reply to
SEARCH requests that do not list ``tls`` among their supported protocols.  A ``tcp``-only
search therefore receives no answer at all — the server behaves as if its plaintext port
were blocked by a firewall.  The token is read once at server construction and is fixed for
the lifetime of the process; changing the policy requires a restart.  A startup log line,
``transport: tls-only (plaintext TCP listener disabled)``, confirms that the policy is in
effect.

``no_tcp`` is a *transport*-axis control and is independent of the ``client_cert=require``
*authentication*-axis control in the same variable.  The two combine into four postures:

* neither — both transports, anonymous TLS clients accepted (the default).
* ``client_cert=require`` only — plaintext TCP is still up, so anonymous clients can still
  reach the server over TCP.  This is the "TCP up + cert required" trap: requiring a client
  certificate does **not** by itself stop plaintext access.  ``no_tcp`` exists to close that
  gap.
* ``no_tcp`` only — plaintext TCP is closed, but anonymous TLS clients are still accepted.
  Because this is a weakened posture, the server logs a single startup warning noting that
  anonymous TLS clients will still be accepted.
* ``no_tcp client_cert=require`` (either order) — fully locked down: TLS transport only, and
  every client must present a valid certificate.  No warning is emitted for this combination.

``no_tcp`` is *operator policy* and must not be confused with the cert-status-driven
``TcpOnly`` state (``tcp-only-cert-state``).  ``no_tcp`` is static, set deliberately at
startup, and permanent for the process lifetime.  ``TcpOnly`` is dynamic cert *state*, driven
by PVACMS status notifications, and reflects that the server's own certificate is not yet
usable for TLS.  If a server is configured with ``no_tcp`` while its certificate resolves to
``TcpOnly``, it will be unreachable until the certificate becomes valid; this is the intended
security posture (never fall back to plaintext), and the server logs a warning so the
condition is visible.

.. _addrspec:

Address Spec.
-------------

Space separated entries in **EPICS_PVA*_ADDR_LIST** variables must be in one of the following forms:

* ``<ip4-or-host>[:<port#>][,TTL#][@ifacename]``
* ``"["<ip6-or-host>"]"[:<port#>][,TTL#][@ifacename]``

Examples include:

``myhost``
    Lookup hostname at startup, use default port number.
    Use OS routing table.

``10.1.1.1:5076``
    Explicit IPv4 address and port number.
    Use OS routing table.

``[2600:1234::42]``
    Explicit IPv6 address with default port.
    Use OS routing table.

``224.0.2.3,255@192.168.1.1``
    IPv4 multicast address, with Time To Live set to 255.
    Send via the network interface with address ``192.168.1.1``.
    Use default port number.

``[ff02::42:1],1@br0``
    IPv6 multicast address, with Time To Live set to 1 (roughly equivalent to IPv4 broadcast).
    Send via the network interface named ``br0``.
    Use default port number.

.. _netconfbg:

PV Search Process
-----------------

A PV Access network protocol operation proceeds in two phases:
PV name resolution, and data transfer.
Name resolution is the process is determining which PVA server claims to provide each PV name.
Once this is known, a TCP connection is open to that server, and the operation(s) are executed.

The PVA Name resolution process is similar to Channel Access protocol.

When a name needs to be resolved, a PVA client will begin sending UDP search messages to any addresses
listed in ``$EPICS_PVA_ADDR_LIST`` and also via TCP to any servers listed in ``$EPICS_PVA_NAME_SERVERS``
which can be reached.

UDP searches are by default sent to port **5076**, subject to ``$EPICS_PVA_BROADCAST_PORT`` and
port numbers explicitly given in ``$EPICS_PVA_ADDR_LIST``.

The addresses in ``$EPICS_PVA_ADDR_LIST`` may include IPv4/6 unicast, multicast, and/or broadcast addresses.
By default (cf. ``$EPICS_PVA_AUTO_ADDR_LIST``) the address list is automatically populated
with the IPv4 broadcast addresses of all local network interfaces.

Searches will be repeated periodically in perpetuity until a positive response is received,
or the operation is cancelled.

In order to reduce the number of broadcast packets, which every PVA host must process,
the time between searches will initially be short, then gradually increase
as time passes without a positive response.

Server beacon destinations are by default configured using the client configuration.
This may be overridden with ``$EPICS_PVAS_BEACON_ADDR_LIST`` and ``$EPICS_PVAS_AUTO_BEACON_ADDR_LIST``.
