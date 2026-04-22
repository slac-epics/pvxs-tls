# Robust Certificate State Management

## Executive Summary

We propose a new `SUSPENDED` certificate status class that allows TLS
connections to remain open when a certificate transitions to `SCHEDULED_OFFLINE`
or `PENDING_RENEWAL`, rather than disconnecting or falling back to TCP.
Operations are suspended transparently and resume automatically when the
certificate returns to `VALID` — with no reconnect, no new TLS handshake, and
no disruption to QSRV or IOC records.

This is a pvxs library change. PVACMS already publishes the correct status
values; the client and server connection layers need to know what to do with
them.

---

## Background and Motivation

### The three-class problem

The existing `cert_status_class_t` has three values:

| Class | Value | Current mapping |
|---|---|---|
| `BAD` | -1 | `REVOKED`, `EXPIRED` → disconnect |
| `UNKNOWN` | 0 | Everything else → wait indefinitely |
| `GOOD` | 1 | `VALID` → proceed |

`SCHEDULED_OFFLINE` and `PENDING_RENEWAL` both fall into `UNKNOWN`, which
causes the client to defer channel creation indefinitely with no progress and
no feedback to the application.

### Why TCP fallback is wrong

These two states are *temporal* — the certificate is still cryptographically
valid and will return to `VALID` again:

- **`SCHEDULED_OFFLINE`**: cert is valid; operationally offline by schedule
- **`PENDING_RENEWAL`**: cert is valid; past `renew_by` date, renewal in flight

Falling back to TCP would:
- Lose the security context (server may require TLS)
- Require a full reconnect and new TLS handshake when the window reopens
- Leave clients on TCP indefinitely if the schedule window detection is missed

### The four-path problem

Suspension affects four distinct certificate monitoring paths, each requiring
its own response:

1. **Client monitoring its own cert** — client needs to suspend outbound
   operations on all connections
2. **Client monitoring peer (server) cert** — client needs to suspend inbound
   operations on that specific connection
3. **Server monitoring its own cert** — server needs to pause monitor updates
   and reject PUT/RPC on all connections
4. **Server monitoring peer (client) cert** — server needs to defer channel
   validation without disrupting existing operations

---

## The SUSPENDED Class

### New `cert_status_class_t` value

```cpp
enum class cert_status_class_t : int {
    BAD       = -1,  // REVOKED, EXPIRED — disconnect
    UNKNOWN   =  0,  // PENDING, PENDING_APPROVAL, UNKNOWN — wait
    SUSPENDED =  2,  // SCHEDULED_OFFLINE, PENDING_RENEWAL — pause, keep TLS
    GOOD      =  1,  // VALID — proceed normally
};
```

`SUSPENDED = 2` preserves the existing sign semantics (negative = bad, zero =
unknown, positive = good). Both 1 and 2 represent cryptographically valid
certificates; 2 is "valid but operationally offline".

### Status classification

| Certificate status | Class | Rationale |
|---|---|---|
| `VALID` | `GOOD` | Normal operation |
| `SCHEDULED_OFFLINE` | `SUSPENDED` | Valid cert, offline by schedule |
| `PENDING_RENEWAL` | `SUSPENDED` | Valid cert, past renew_by date |
| `UNKNOWN` | `UNKNOWN` | Genuinely unknown — wait |
| `PENDING` | `UNKNOWN` | Not yet activated — wait |
| `PENDING_APPROVAL` | `UNKNOWN` | Awaiting approval — wait |
| `EXPIRED` | `BAD` | No longer valid — disconnect |
| `REVOKED` | `BAD` | Permanently invalid — disconnect |

---

## Client Behaviour

### Path 1: Client monitoring peer (server) cert — `Connection::peerStatusCallback()`

| Transition | Action |
|---|---|
| Any → `GOOD` | Proceed with channel creation. If previously `SUSPENDED`, resume all paused monitors; clear `suspended_monitors` list. No reconnect. |
| Any → `SUSPENDED` | Keep TLS socket open. Pause all `Running` monitors via `pause(true)`; record in `suspended_monitors`. Set `suspended_by_cert = true`. Defer new channel creation. |
| Any → `BAD` | Clear `suspended_monitors`. Call `disconnect()` normally. |
| Any → `UNKNOWN` | Defer channel creation. No disconnect. (unchanged) |

**New data per `Connection`:**
- `std::vector<std::weak_ptr<Subscription>> suspended_monitors`
- `bool suspended_by_cert = false`

### Path 2: Client monitoring own cert — `ContextImpl::onSuspended()` / `onResumed()`

When the client's own entity cert enters `SUSPENDED`, `SSLContext` fires an
`on_suspended_` callback. `ContextImpl` registers this callback and dispatches
`peerStatusCallback(SUSPENDED)` on every live `Connection` via the TCP loop —
reusing the exact same per-connection suspension path as Path 1.

On resume (`GOOD`), `ContextImpl::onResumed()` dispatches
`peerStatusCallback(GOOD)` on all connections.

### Operation behaviour during SUSPENDED

| Operation | Behaviour |
|---|---|
| **Monitor** | Paused. No updates delivered. On `GOOD`, missed updates delivered immediately on resume. |
| **GET** (cached value exists) | Returns last cached value with `alarm.severity = INVALID` |
| **GET** (no cached value) | Returns error: `"Connection suspended: no cached value"` |
| **PUT** | Fails immediately: `"Connection suspended: certificate SCHEDULED_OFFLINE / PENDING_RENEWAL"` |
| **RPC** | Fails immediately: same error as PUT |
| **New channel creation** | Deferred (same as `UNKNOWN`) |

### SSLContext — own cert SUSPENDED (`setTlsOrTcpMode()`)

When the entity's own cert enters `SUSPENDED`:
- `SSLContext::state` **stays `TlsReady`** — does NOT downgrade to `TcpReady`
- New TLS handshakes continue to be accepted (cert is still cryptographically valid)
- `on_suspended_` callback fires via libevent event on the context loop
- On `GOOD` after `SUSPENDED`: `on_resumed_` callback fires; `on_resumed_` is
  only fired if the prior state was SUSPENDED (tracked via `was_suspended` local)

---

## Server Behaviour

### Path 3: Server monitoring own cert — `ServerConn::suspendedByOwnCert()` / `resumedByOwnCert()`

When `SSLContext` fires `on_suspended_`, `Server::Pvt` calls
`suspendedByOwnCert()` on every active `ServerConn`:

| Operation | Behaviour when `suspended_by_cert == true` |
|---|---|
| **Monitor** | Stops sending updates to the client |
| **GET** (cached value exists) | Returns cached value with `alarm.severity = INVALID` |
| **GET** (no cached value) | Returns `Status::Error` with suspension message |
| **PUT** | Rejected: `"Server suspended: certificate SCHEDULED_OFFLINE / PENDING_RENEWAL"` |
| **RPC** | Rejected: same error as PUT |

On `resumedByOwnCert()`:
- All monitors paused by `suspendedByOwnCert()` resume
- `suspended_by_cert` cleared
- No disconnect, no reconnect
- **QSRV and IOC records see no disruption throughout** — no `onClose` callbacks
  are fired because `disconnect()` is never called

**New data per `ServerConn`:**
- `bool suspended_by_cert = false`

### Path 4: Server monitoring peer (client) cert — `ServerConn::peerStatusCallback()`

When the connecting client's cert is `SUSPENDED`:
- Server logs a warning and defers `proceedWithConnectionValidation()` (same
  as `UNKNOWN`)
- Does NOT close the connection
- Does NOT pause or cancel any active server-side operations
- QSRV and IOC records are **completely unaffected** — no channel disruption,
  no `onClose` callbacks
- On `GOOD`: calls `proceedWithConnectionValidation()` normally

This is intentional: the server cannot know whether the client's suspended cert
means the client should be restricted. The validation deferral is the safe
default; future policy extensions can add finer-grained server-side responses.

---

## State Transition Diagram

```
                    ┌─────────────────────────────────────────┐
                    │           SUSPENDED state               │
                    │  • TLS socket: OPEN                     │
                    │  • Monitors: PAUSED                     │
                    │  • GET: stale + INVALID alarm           │
                    │  • PUT/RPC: rejected                    │
                    │  • New channels: deferred               │
                    └────────────┬────────────────────────────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
            → GOOD          → UNKNOWN        → BAD
                 │               │               │
                 ▼               ▼               ▼
           RESUME           WAIT            DISCONNECT
        (no reconnect)   (unchanged)     (as before)
```

```
Certificate status → Class → Client action → Server action
─────────────────────────────────────────────────────────
VALID              GOOD      Resume / proceed   Resume / validate
SCHEDULED_OFFLINE  SUSPENDED Suspend            Suspend own / defer peer
PENDING_RENEWAL    SUSPENDED Suspend            Suspend own / defer peer
UNKNOWN/PENDING/…  UNKNOWN   Defer channels     Defer validation
EXPIRED/REVOKED    BAD       Disconnect         (connection already closed)
```

---

## SSLContext Callback Architecture

```
SSLContext::setTlsOrTcpMode(SUSPENDED)
    └── fires on_suspended_ event (libevent)
            │
            ├── Client: ContextImpl::onSuspended()
            │       └── iterates connByAddr
            │               └── Connection::peerStatusCallback(SUSPENDED)
            │                       → pause monitors, set suspended_by_cert
            │
            └── Server: Server::Pvt (registered at startup)
                    └── iterates connections
                            └── ServerConn::suspendedByOwnCert()
                                    → pause monitors, reject PUT/RPC

SSLContext::setTlsOrTcpMode(GOOD) after SUSPENDED
    └── fires on_resumed_ event (libevent)
            │
            ├── Client: ContextImpl::onResumed()
            │       └── Connection::peerStatusCallback(GOOD)
            │               → resume paused monitors, clear suspended_monitors
            │
            └── Server: Server::Pvt
                    └── ServerConn::resumedByOwnCert()
                            → resume monitors, clear suspended_by_cert
```

---

## Files Changed in pvxs

| File | Change |
|---|---|
| `src/certstatus.h` | Add `SUSPENDED = 2` to `cert_status_class_t`; update `getStatusClass()` |
| `src/openssl.h` | Add `on_suspended_`, `on_resumed_` callbacks; `suspended_event`, `resumed_event` libevent members; setter methods |
| `src/openssl.cpp` | `setTlsOrTcpMode()` SUSPENDED case; `on_resumed_` fires on GOOD-after-SUSPENDED; `suspendedEventCallback` / `resumedEventCallback` static; audit GOOD→UNKNOWN suppression guard does not suppress GOOD→SUSPENDED |
| `src/clientimpl.h` | `onSuspended()`, `onResumed()` on `ContextImpl`; `suspended_monitors`, `suspended_by_cert` on `Connection` |
| `src/client.cpp` | Implement `onSuspended()`, `onResumed()`; register `on_suspended_`/`on_resumed_` at `setOnTlsReady` sites |
| `src/clientconn.cpp` | `SUSPENDED` branch in `peerStatusCallback()`; GOOD branch resume path; PUT/RPC rejection; stale-GET path; `cleanup()` clears `suspended_monitors` |
| `src/conn.h` / `src/conn.cpp` | Document that `isPeerStatusGood()` returning false covers both `UNKNOWN` and `SUSPENDED` |
| `src/serverconn.h` | `suspended_by_cert`; `suspendedByOwnCert()`, `resumedByOwnCert()` declarations |
| `src/serverconn.cpp` | `SUSPENDED` branch in `peerStatusCallback()`; `suspendedByOwnCert()`/`resumedByOwnCert()` implementations; PUT/RPC/GET guards |
| `src/server.cpp` | Register `on_suspended_`/`on_resumed_` callbacks at startup |

All switch statements on `cert_status_class_t` are audited for exhaustiveness.

---

## Relationship to Validity Schedules

The `SUSPENDED` class is the connection-layer mechanism that makes validity
schedules (see `VALIDITY_SCHEDULES.md`) safe to use in production.  Without
`SUSPENDED`, a cert entering `SCHEDULED_OFFLINE` would leave pvxs in the
`UNKNOWN` wait state — connections would never progress and monitors would
never receive updates.  With `SUSPENDED`, the transition is clean:

1. PVACMS evaluates the schedule window and posts `SCHEDULED_OFFLINE`
2. pvxs receives the status update and enters `SUSPENDED`
3. Monitors pause; PUT/RPC are rejected; GET returns stale value with alarm
4. When the next schedule window opens, PVACMS posts `VALID`
5. pvxs receives `GOOD`, resumes monitors, re-enables all operations
6. No reconnect, no new TLS handshake, no QSRV disruption

The same mechanism applies to `PENDING_RENEWAL`: the cert's operational
suspension during the renewal window is handled identically, and normal
operation resumes the moment the renewed certificate is issued.

---

## Testing

The openspec tasks define 10 test scenarios (`tasks.md` §9):

- `getStatusClass()` returns `SUSPENDED` for `SCHEDULED_OFFLINE` and
  `PENDING_RENEWAL`
- Client peer cert SUSPENDED: socket open, monitors paused, PUT/RPC rejected,
  stale INVALID-alarm GET
- Client own cert SUSPENDED: `onSuspended()` fires, all connections suspended
- SUSPENDED→GOOD: monitors resume, no reconnect
- SUSPENDED→BAD: `disconnect()` called, monitors cleaned up
- Server own cert SUSPENDED: monitors stop, PUT/RPC rejected, GET returns stale
- Server own cert SUSPENDED→GOOD: monitors resume, QSRV uninterrupted
- Server own cert SUSPENDED→BAD: `setDegradedMode()`, connections closed
- Server peer cert SUSPENDED: validation deferred, no channel disruption
- Switch exhaustiveness: all `cert_status_class_t` switches handle `SUSPENDED`

---

## References

| Resource | Location |
|---|---|
| OpenSpec change | `../pvxs/openspec/changes/suspended-cert-status/` |
| Proposal | `proposal.md` |
| Design decisions | `design.md` |
| Implementation tasks | `tasks.md` |
| Capability spec | `specs/suspended-cert-status/spec.md` |
| Modified cert-status spec | `specs/certificate-status/spec.md` |
| Companion feature | `docs/VALIDITY_SCHEDULES.md` |
