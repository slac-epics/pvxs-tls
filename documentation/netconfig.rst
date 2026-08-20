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

Disabling transports
--------------------

The server port variables accept the special value ``NO`` to disable the corresponding
transport for the lifetime of the process (read once at server construction; changing the
policy requires a restart):

* ``EPICS_PVAS_SERVER_PORT=NO`` disables the plaintext PVAccess TCP listener.  The server
  only accepts TLS connections; SEARCH replies advertise only the TLS endpoint, and a
  ``tcp``-only SEARCH receives no claim.  Discovery works via UDP (if enabled) or a TLS
  name-server connection: ``EPICS_PVA_NAME_SERVERS=pvas://host[:tls_port]`` (the TLS port
  accepts ordinary TCP connections and runs the TLS handshake on each; SEARCH is served
  over the established TLS connection).  Beacons continue to advertise the configured
  plaintext port with protocol ``tcp`` (liveness ping only).  A startup log line,
  ``transport: tls-only (plaintext TCP listener disabled)``, confirms the policy is in
  effect.
* ``EPICS_PVAS_TLS_PORT=NO`` disables TLS.
* ``EPICS_PVAS_BROADCAST_PORT=NO`` disables the UDP search listeners and beacons; discovery
  then requires a name server.

The negation token is case-insensitive (``NO``, ``no``, ``off``, ``false``, ``disabled``).
These values apply to servers only; clients ignore them.

Name servers for peer certificate status
----------------------------------------

A server presented with a client certificate asks the certificate manager that issued it
whether it still stands, and it does that with an inner client of its own. Where that
certificate manager cannot be reached from where the server stands, as with a peer
department behind a gateway, ``$EPICS_PVAS_STATUS_NAME_SERVERS`` names something that can
answer for it:

* it is read into ``server::Config::statusNameServers`` and used by the inner client alone,
  so it affects certificate status and nothing else the process does;
* left unset, the inner client falls back to ``$EPICS_PVA_NAME_SERVERS`` from the process
  environment, which is the behaviour it has always had;
* it is the only route for a server whose configuration is supplied programmatically rather
  than through the environment. The p4p gateway is the case that matters: it builds its
  server from a configuration file with ``useenv=False``, and any key beginning ``EPICS_PVA``
  in the server section of that file is passed through to the server configuration.

A server whose own certificate manager is reachable needs none of this; searching finds it.

Disabling both TCP and TLS leaves no transport to serve and is a fatal error at server
construction.

Disabling TCP is a *transport*-axis control, independent of the ``client_cert=require``
*authentication*-axis control:

* neither — both transports, anonymous TLS clients accepted (the default).
* ``client_cert=require`` only — plaintext TCP is still up, so anonymous clients can still
  reach the server over TCP.  Requiring a client certificate does **not** by itself stop
  plaintext access; disabling TCP exists to close that gap.
* ``EPICS_PVAS_SERVER_PORT=NO`` only — plaintext TCP is closed, but anonymous TLS clients
  are still accepted.  The server logs a single startup warning for this weakened posture.
* both — fully locked down: TLS transport only, every client must present a valid
  certificate.  No warning is emitted.

Disabling TCP is *operator policy* and must not be confused with the cert-status-driven
``TcpOnly`` state (``tcp-only-cert-state``), which is dynamic cert *state* driven by PVACMS
status notifications.  A server with TCP disabled whose certificate resolves to ``TcpOnly``
is unreachable until the certificate becomes valid; this is the intended security posture
(never fall back to plaintext), and the server logs a warning so the condition is visible.

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
