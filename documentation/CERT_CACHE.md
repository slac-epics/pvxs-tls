# Certificate Status Cache

## Executive Summary

We propose adding a disk-based cache of signed OCSP response bytes to
`CertStatusManager`.  On every process restart, all certificate status subscriptions
currently start cold — there is a window of unknown duration during which connections
may be delayed or rejected because valid status cannot be confirmed for either the
process's own certificate or for peer certificates it is monitoring.

The fix is straightforward: persist the raw signed OCSP response bytes to small per-
certificate files on disk.  On the next `subscribe()` call, if a valid cached response
exists, deliver it to the callback immediately before the PV subscription is
established.  The signed OCSP response is cryptographically self-validating against the
trusted store — no additional integrity mechanisms are needed.

This is an entirely additive change.  Processes without a cache behave exactly as they
do today.  The cache directory follows the existing XDG convention already used by pvxs
for identity files.  No new external dependencies are introduced.

---

## Background and Motivation

### Certificate status in PVXS TLS

When PVXS operates with TLS enabled, certificate validity is not established by
expiry date alone.  PVACMS issues OCSP responses via PV subscriptions (OCSP-over-PVA,
described in `documentation/oscp.md`).  The `CertStatusManager` class in
`src/certstatus.h` manages these subscriptions.  When a pvxs client or server calls
`subscribe()` for a certificate, `CertStatusManager`:

1. Opens a PV subscription to the PVACMS status PV for that certificate
2. Waits for the first response
3. Parses and verifies the OCSP response against the trusted store
4. Delivers a `PVACertificateStatus` to a callback

The callback drives the TLS connection machinery: connections to peers are held pending
until a `GOOD` (and current) status is confirmed for both sides.

### The cold-start problem

On every process restart, step 2 above requires a network round-trip to PVACMS.
During the time between process start and the first PV subscription update, certificate
status is `UNKNOWN`.  In a well-connected environment this window is typically short —
a few hundred milliseconds — but it is not zero, and in some scenarios it is
significant:

- **PVACMS is slow to respond** (heavy load, cluster failover)
- **Network partitions** between the pvxs process and PVACMS
- **Rapid restart cycles** (watchdog-driven IOC restarts)
- **Tool invocations** (`pvxget`, `pvxput`) that need to make a single connection
  quickly

The OCSP response from PVACMS has a defined validity window (`thisUpdate` /
`nextUpdate`).  A recently received `GOOD` response remains cryptographically valid
until `nextUpdate`.  There is no reason to discard this information on process exit
when it can be trivially persisted to disk and reloaded on the next startup.

### Why not an in-memory cache?

In-memory caching is already implicit in the subscription lifetime: once
`CertStatusManager` has received a valid response, it holds the status until the
process exits.  The problem is the cold-start window on restart.  An in-memory cache
does not survive process restart; a disk cache does.

---

## Scope of Changes

### What changes

1. **`src/statuscache.h`** (new file) — Declares the cache I/O API:
   `getStatusCacheDir()`, `isStatusCacheEnabled()`, `writeCacheFile()`,
   `readCacheFile()`, `deleteCacheFile()`
2. **`src/statuscache.cpp`** (new file) — Implements the above: atomic write via
   temp-file-then-rename, advisory file locking, XDG directory resolution, environment
   variable handling
3. **`src/certstatus.h`** — `CertStatusManager` gains a `cached_ocsp_bytes_` member
   for change-detection
4. **`src/certstatus.cpp`** — Two integration points:
   - In `subscribe()`: cache-read-before-subscribe path
   - In the subscription event callback: cache-write-on-update path
5. **`test/teststatuscache.cpp`** — Unit tests for all cache I/O paths

### What does not change

- The PVAccess wire protocol
- The `CertStatusManager` public API (the `subscribe()` signature is unchanged)
- Non-OpenSSL builds (cache is a no-op)
- Any behaviour when no cache file exists (identical to current)

---

## Detailed Design

### Cache storage — per-certificate `.ocsp` files

Each cached OCSP response is stored in a separate file:

```
${XDG_DATA_HOME}/pva/1.5/status_cache/<cert_id>.ocsp
```

The `cert_id` is the value returned by `CertStatusManager::getCertIdFromCert()` —
a string encoding the issuer authority identity and the certificate serial number
(e.g. `"myCA:0x00001234"`).  This is already used throughout `CertStatusManager` as
the canonical key for a certificate.

Cache files contain only the raw DER-encoded signed OCSP response bytes, exactly as
received from the PVACMS PV subscription.  These bytes are cryptographically self-
validating: on load, they are passed through the existing `OCSP_basic_verify()` path
against the trusted store.  A corrupted or tampered file simply fails verification and
is discarded, with no harm done.

**Why individual files rather than a SQLite table?**  pvxs clients and servers do not
carry a SQLite database.  Individual files are portable, require no schema migrations,
and allow independent update and simpler advisory locking per certificate.  File sizes
are small (typically 1–3 KB for a PVACMS-issued OCSP response).  A single flat file
for all certificates was considered but rejected because independent update and deletion
is cleaner with per-certificate files.

**Why XDG data directory?**  This is already the convention used by pvxs for identity
files and the `certs.db` database.  Using the same base directory keeps all pvxs
persistent state co-located and makes it easy to find, audit, or purge.

### Cache integration in subscribe()

Before establishing the PV subscription, `subscribe()` checks for a cache file:

```cpp
if (isStatusCacheEnabled()) {
    try {
        auto cached_bytes = readCacheFile(cert_id);
        if (!cached_bytes.empty()) {
            PVACertificateStatus cached_status(
                VALID, buf.freeze(), trusted_store_ptr, cert_id);

            if (cached_status.isStatusCurrent()) {
                cert_status_manager->cached_ocsp_bytes_ = std::move(cached_bytes);
                cert_status_manager->status_ = std::make_shared<CertificateStatus>(cached_status);
                (*cert_status_manager->callback_ref)(cached_status);
            } else {
                deleteCacheFile(cert_id);  // expired — clean up
            }
        }
    } catch (std::exception &e) {
        deleteCacheFile(cert_id);  // corrupt — clean up
    }
}
// PV subscription established regardless, to receive live updates
```

**The PV subscription is always established even after a cache hit.**  This is
intentional: the cache provides an immediate status on startup, but the live
subscription will deliver updates (including revocation) and eventually refresh the
cache.  The cache only eliminates the latency of the first update; it does not replace
the subscription mechanism.

**If the cache file is expired (`isStatusCurrent()` returns false), it is deleted
immediately.**  The process then waits for the first live PV update, exactly as today.

**If OCSP verification fails (corrupted or tampered file), the file is deleted and
a debug log message is emitted.**  The process proceeds without cached status.  The
cryptographic verification is the sole integrity mechanism — no checksums or secondary
validation are needed.

### Cache-write in the subscription event callback

When the subscription callback receives a valid OCSP response, it writes to the cache:

```cpp
if (isStatusCacheEnabled() && status_update.isStatusCurrent()) {
    const auto *new_data = status_update.ocsp_bytes.data();
    const auto new_size  = status_update.ocsp_bytes.size();

    // Avoid redundant writes: only write if the new response differs
    // from what we already have in memory (which reflects what was last
    // written to disk by this process)
    if (new_size != csm->cached_ocsp_bytes_.size() ||
        std::memcmp(new_data, csm->cached_ocsp_bytes_.data(), new_size) != 0) {
        // Re-read from disk first in case another process already wrote
        // the same response (common in clustered deployments)
        auto on_disk = readCacheFile(cert_id);
        if (on_disk.size() != new_size ||
            std::memcmp(on_disk.data(), new_data, new_size) != 0) {
            writeCacheFile(cert_id, new_data, new_size);
        }
        csm->cached_ocsp_bytes_.assign(new_data, new_data + new_size);
    }
}
```

**Only current, verified responses are cached** — the outer `isStatusCurrent()` check
ensures that an expired or UNKNOWN status response never touches the cache.  The
existing OCSP parse/verify path (which already runs before this point in the callback)
ensures the bytes are cryptographically valid before we see them here.

**Change detection before writing** avoids a disk write on every subscription update
when the OCSP response has not changed.  PVACMS refreshes OCSP responses periodically
(advancing `nextUpdate`); each such refresh produces new bytes even for an unchanged
`GOOD` status.  The in-memory `cached_ocsp_bytes_` reflects the last bytes written,
so a simple byte-comparison catches the common case where the same response is
re-delivered.

**Read-before-write for multi-process safety** handles the case where multiple pvxs
processes on the same host share the same cache directory and subscribe to the same
certificate.  If a concurrent process has already written the same response, we skip
the write.  This is a best-effort optimisation; the advisory lock in `writeCacheFile()`
provides the hard safety guarantee.

### Concurrent access — atomic write and advisory locking

`writeCacheFile()` uses the standard write-to-temp-then-rename pattern:

1. Write bytes to `<cert_id>.ocsp.tmp` in the cache directory
2. Close the temp file
3. Atomically replace `<cert_id>.ocsp` with the temp file

The rename step is platform-specific:

- **POSIX** (Linux, macOS): `rename(2)` is specified by POSIX.1-2017 to atomically
  replace the destination if it exists.  A concurrent reader always sees either the
  complete old file or the complete new file — never a partial write.
- **Windows**: `rename()` / `MoveFile()` refuse to replace an existing destination
  (`ERROR_ALREADY_EXISTS`).  `writeCacheFile()` instead calls
  `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`, which provides the same
  atomic-replace semantics on Windows.  This was a latent bug in the original
  implementation (raised by @mdavidsaver) — without this fix the write would silently
  fail whenever a cache file already existed, leaving stale data on disk indefinitely.

Advisory file locking (via the `FLock` RAII helper from `utilpvt.h`) holds
`LOCK_EX` on the temp file during write and `LOCK_SH` on the cache file during read.
On platforms where `USE_POSIX_FLOCK` is not defined (including Windows), `FLock` is a
no-op; the atomic rename is the hard safety guarantee in that case.

The cache directory is created with mode `0700` (owner-only) on first write to limit
exposure of cert status information to other users on the same host.

### Configuration

| Environment variable         | Default                                  | Meaning                                                  |
|------------------------------|------------------------------------------|----------------------------------------------------------|
| `EPICS_PVA_STATUS_CACHE_DIR` | `${XDG_DATA_HOME}/pva/1.5/status_cache/` | Cache directory path                                     |
| `EPICS_PVA_NO_STATUS_CACHE`  | (unset)                                  | Set to `YES`, `TRUE`, or `1` to disable caching entirely |

These follow the existing `EPICS_PVA_*` naming convention.  The `XDG_DATA_HOME` fallback
itself uses the XDG convention: `~/.local/share` when `XDG_DATA_HOME` is unset, which
is what pvxs already uses for identity files.

The implementation lives in `getStatusCacheDir()` and `isStatusCacheEnabled()` in
`src/statuscache.cpp`, keeping the configuration logic isolated from the
`CertStatusManager` core.

### Non-OpenSSL builds

All cache operations are guarded by the same `#ifdef PVXS_ENABLE_OPENSSL` preprocessor guards  and `EVENT2_HAS_OPENSSL` 
Makefile Macros that protect the rest of `CertStatusManager`.  In a non-OpenSSL build, `subscribe()`, `readCacheFile()`, 
and `writeCacheFile()` won't be compiled in.

---

## Security Considerations

### Stale-on-revocation window

A cached `GOOD` OCSP response remains valid until its `status_valid_until_date`
(`nextUpdate`), regardless of whether the certificate has been revoked in the interim.
This is by design: it is identical to the behaviour without caching.  The OCSP validity
period is the trust window, and PVACMS is responsible for issuing short-lived responses
and delivering revocations via the live PV subscription promptly.

Once the live PV subscription delivers a revocation update, the cache will be
overwritten with the revoked status and will not be served again (since `isStatusCurrent()`
will be false for a revoked certificate).

### Cache directory permissions

The cache directory is created with `0700` (owner-only access).  This prevents other
users on a shared host from reading cached OCSP responses, which could reveal
information about which certificates are in use.  The files themselves contain only
signed OCSP responses, not private keys or credentials.

### Cryptographic self-validation

The cache provides no integrity mechanism beyond the cryptographic signature on the
OCSP response itself.  This is sufficient: a tampered file will fail `OCSP_basic_verify()`
against the trusted store and be discarded.  Adding checksums or MACs would provide no
additional security value and would complicate the implementation.

---

## Migration and Rollback

All changes are additive.  The migration path is:

1. **No cache files exist** → `subscribe()` finds nothing; behaviour is identical to
   today.
2. **Cache files exist, process starts** → Valid cached responses are delivered
   immediately; expired or corrupt files are silently discarded.
3. **First-time write** → Cache directory is created on the first successful PV
   subscription update.

**Rollback** requires removing the cache code from `certstatus.cpp` and deleting the
`src/statuscache.h` / `src/statuscache.cpp` files.  Leftover `.ocsp` files in the cache
directory are harmless — they will never be read without the cache code.

---

## Relationship to the PVACMS SAN-in-CCR Feature

This change is independent of the SAN-based access control feature
(`documentation/SAN_SUPPORT.md`).  However, both features are developed on branches
that build on top of the same base (`main`, formerly `tls`), and the `feature/cert-caching` branch is
rebased on top of `feature/san` so that both features can be reviewed together.

There is no logical dependency: the cert status cache works identically regardless of
whether SAN values are present in peer certificates.

---

## Testing

The implementation is covered by `test/teststatuscache.cpp` which exercises:

- Write and read-back of OCSP bytes (round-trip)
- Expired cache file detected and discarded
- Corrupted cache file detected and discarded (bad signature)
- `EPICS_PVA_STATUS_CACHE_DIR` override respected
- `EPICS_PVA_NO_STATUS_CACHE=YES` disables all cache I/O
- Cache directory created on first write with correct permissions
- Concurrent write and read via atomic rename (no partial reads)
- Callback receives cached status immediately on `subscribe()` when cache is valid

---

## References

| Resource | Location |
|----------|----------|
| pvxs cert status cache commit | commit `4566b4d1` — "Add disk-based OCSP response caching with test coverage" |
| `CertStatusManager` class | `src/certstatus.h` |
| Cache I/O utilities | `src/statuscache.h`, `src/statuscache.cpp` |
| OCSP-over-PVA design notes | `documentation/oscp.md` |
| XDG Base Directory Specification | https://specifications.freedesktop.org/basedir-spec/latest/ |
| OpenSSL `OCSP_basic_verify()` | OCSP response verification API used in `src/certstatus.cpp` |
| OpenSpec change | `openspec/changes/cert-status-cache/` |
| Companion SAN feature | `documentation/SAN_SUPPORT.md` |
