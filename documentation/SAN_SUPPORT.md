# SAN-Based Access Control for TLS Peers

## Executive Summary

We propose extending PVXS's TLS credential pipeline to extract Subject Alternative
Name (SAN) values from peer X.509 certificates and make them available for
access-control decisions.  This is a narrowly scoped, additive change: it does not
alter the wire protocol, does not introduce new dependencies, and does not break any
existing ACF configuration.

The motivation arises from a gap in the current identity-extraction path: when PVACMS
issues certificates that carry `iPAddress` and `dNSName` SAN extensions, those values
are silently discarded by `getPeerCredentials()`.  Access security rules therefore
cannot reference the cryptographically-bound network identity of a connecting peer —
only its Common Name and role chain.  For large facilities (such as SLAC) that need to
restrict PV access by subnet or by specific host, this is a significant limitation.

The change spans three layers:

| Layer | Component | Change |
|-------|-----------|--------|
| pvxs (this repo) | `src/openssl.cpp`, `src/pvxs/netcommon.h` | Extract SANs from peer cert; expose via `PeerCredentials::san` |
| pvxs IOC layer (this repo) | `ioc/pvxs/credentials.h`, `ioc/credentials.cpp`, `ioc/securityclient.cpp` | Propagate SANs to asLib identity |
| EPICS Base | `modules/libcom/src/as/asLib.h`, `asLibRoutines.c`, `asLib.y` | New SAG grammar; `EPICS_ASLIB_HAS_SAN` compile guard |
| PVACMS | `src/pvacms/pvacms.cpp`, `src/authn/auth.h` | Include SAN entries in CCR; embed in issued X.509 certificates |

The EPICS Base and PVACMS companion changes have been developed in the
`aslib-san-access-groups` and `feat/san-in-ccr` branches respectively (see
[References](#references)).  This document focuses on the pvxs side and explains the
rationale for each decision in enough detail to allow independent review.

---

## Background and Motivation

### The access-control gap

PVXS's TLS implementation already chains certificate Common Names through to the EPICS
access security library (asLib) via `asAddClientIdentity()`.  The `ASGIDENTITY` struct
carries `user`, `host`, `method`, `authority`, and `protocol`.  Administrators can
therefore write UAG and HAG rules that gate PV access on the authenticated account name
or on the connection IP reported by the OS.

However, the OS-reported IP address (the `host` field) reflects the source port of the
TCP connection — not a value that is cryptographically bound to the connecting entity.
In TLS deployments where PVACMS issues certificates with SAN extensions, the certificate
itself carries the authoritative network identity of the entity: IP addresses it is
permitted to use, and DNS names it is permitted to assert.  This is the standard X.509
mechanism for binding network addresses to PKI identities (RFC 5280 §4.2.1.6).

Without SAN extraction, a PVACMS-issued certificate that says "this is IOC01 at
`10.0.1.42` with FQDN `ioc01.slac.stanford.edu`" cannot be used to enforce an access
rule like "only nodes in subnet `10.0.1.0/24` may write to this PV".  The
cryptographically attested network identity is available in the certificate but is
invisible to the access security layer.

### The PVACMS certificate lifecycle (context)

PVACMS (`pvxs-cms`, branch `feat/san-in-ccr`) has been extended to:
- Accept SAN entries (IP addresses, DNS names, hostnames) in the Certificate Creation
  Request (CCR) from all authentication plugins
- Validate those entries (RFC 1035 DNS label rules; `inet_pton` IP validation)
- Embed them as a proper X.509 `SubjectAltName` extension (using `GEN_IPADD` and
  `GEN_DNS` General Name types) in the issued certificate
- Persist SANs in the SQLite database (schema v4 migration, `san` column as JSON)
- Replicate SANs in cluster SYNC messages

This means that by the time a PVACMS-issued certificate reaches the pvxs TLS handshake,
it reliably carries a `SubjectAltName` extension that reflects the identity the
operator declared when requesting the certificate.

### The EPICS Base SAG extension (context)

The companion EPICS Base change (`aslib-san-access-groups`, commit `41ba1367c`) adds a
new ACF definition type: **SAN Access Groups (SAG)**.  The ACF grammar gains a `SAG`
keyword alongside the existing `UAG` (User Access Group) and `HAG` (Host Access Group):

```
SAG(trusted_subnets) {
    IP(10.0.1.0/24),
    IP(172.16.0.0/16),
    IP(2001:db8::1),
    DNS(*.slac.stanford.edu),
    DNS(ioc01.example.com)
}

ASG(WritePVs) {
    RULE(1, WRITE) {
        UAG(operators)
        SAG(trusted_subnets)
    }
}
```

The asLib implementation adds:

- A `EPICS_ASLIB_HAS_SAN` compile-time guard (parallel to the existing
  `EPICS_ASLIB_HAS_IDENTITY`)
- An `ASSAN` struct: `{ enum asSanType type; const char *value; }` where
  `asSanType` is `asSanIP` or `asSanDNS`
- Extension of `ASGIDENTITY` with `const ASSAN *sans` and `int nsans`
- Type-aware matching: IP entries support exact match and IPv4 CIDR subnet notation;
  DNS entries support exact match and glob wildcards (`*`, `?`)
- IPv6 exact-match support; IPv6 CIDR notation is intentionally out of scope for the
  initial release

For pvxs to participate in SAG-based access control, it must: (a) extract SANs from
peer certificates, and (b) pass them via `ASSAN[]` to `asAddClientIdentity()` whenever
EPICS Base defines `EPICS_ASLIB_HAS_SAN`.

---

## Scope of Changes

### What changes

1. **`src/pvxs/netcommon.h`** — New public `SanEntry` struct and `san` field on
   `PeerCredentials`
2. **`src/openssl.cpp`** — SAN extraction in `SSLContext::getPeerCredentials()`
3. **`ioc/pvxs/credentials.h`** — `san` field on IOC `Credentials` class
4. **`ioc/credentials.cpp`** — Constructor copies SANs from `ClientCredentials`;
   adds `san_ip/<value>` and `san_dns/<value>` entries to the `cred` vector
5. **`ioc/securityclient.cpp`** — Conditional `ASSAN` array construction and
   passthrough to `asAddClientIdentity()`
6. **`test/testsan.cpp`** — Unit tests covering all extraction paths

### What does not change

- The PVAccess wire protocol
- Non-TLS connections (SANs are an X.509 concept)
- Certificates without a `SubjectAltName` extension (behaviour is unchanged)
- The existing `asAddClient()` path used when `EPICS_ASLIB_HAS_IDENTITY` is absent

---

## Detailed Design

### SanEntry — the SAN value representation

We introduce a small public struct in `src/pvxs/netcommon.h`:

```cpp
/** A single Subject Alternative Name (SAN) entry from an X.509 certificate.
 *
 * Each entry has a type ("ip" or "dns") and a string value.
 * IP values are in canonical form as produced by inet_ntop().
 * DNS values are lowercased for case-insensitive matching.
 *
 * @since UNRELEASED
 */
struct PVXS_API SanEntry {
    std::string type;   // "ip" or "dns"
    std::string value;  // canonical form
};
```

`PeerCredentials` gains:

```cpp
/** Subject Alternative Name (SAN) entries from the peer's X.509 certificate.
 *  Empty for non-TLS connections or certificates without SAN extensions.
 *  @since UNRELEASED
 */
std::vector<SanEntry> san;
```

**Why a struct vector, not a map?**  A `std::vector<SanEntry>` preserves insertion
order (which matches the ordering in the X.509 extension) and is self-documenting.  A
`std::map<std::string, std::vector<std::string>>` loses ordering and is heavier.
Separate per-type vectors (`san_ips`, `san_dns`) would be less extensible if future SAN
types are needed.  A single formatted string would require downstream parsing.

**ABI note:** Adding a field to `PeerCredentials` changes its layout.  Because pvxs is
on the `tls` branch — not yet ABI-stable for TLS features — this is acceptable.  The
field is default-constructed to empty, so code that does not use it is unaffected.

### SAN extraction in getPeerCredentials()

In `SSLContext::getPeerCredentials()` in `src/openssl.cpp`, after the existing CN and
chain extraction, we add:

```cpp
// Extract Subject Alternative Names (SANs) from the peer certificate.
// Only IP (GEN_IPADD) and DNS (GEN_DNS) types are used; all others are skipped.
if (auto *gens = static_cast<GENERAL_NAMES *>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr))) {
    for (int i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        const GENERAL_NAME *gn = sk_GENERAL_NAME_value(gens, i);
        if (gn->type == GEN_IPADD) {
            // Binary IP address — format via inet_ntop for canonical form
            char buf[INET6_ADDRSTRLEN] = {};
            const uint8_t *data = gn->d.iPAddress->data;
            int len = gn->d.iPAddress->length;
            if (len == 4)
                inet_ntop(AF_INET, data, buf, sizeof(buf));
            else if (len == 16)
                inet_ntop(AF_INET6, data, buf, sizeof(buf));
            if (buf[0])
                cred.san.push_back({"ip", buf});
        } else if (gn->type == GEN_DNS) {
            std::string dns(reinterpret_cast<const char *>(
                                ASN1_STRING_get0_data(gn->d.dNSName)),
                            ASN1_STRING_length(gn->d.dNSName));
            // Lowercase for case-insensitive matching (RFC 4343;
            // EPICS Base SAG lowercases all entries at ACF parse time)
            for (auto &c : dns)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            cred.san.push_back({"dns", std::move(dns)});
        }
        // GEN_EMAIL, GEN_URI, etc. are silently skipped
    }
    GENERAL_NAMES_free(gens);
}
```

**Why extract only `GEN_IPADD` and `GEN_DNS`?**  These are the only types defined by
the EPICS Base SAG implementation (`asSanIP`, `asSanDNS`) and the only types that are
meaningful for network-level access control in an EPICS context.  Email and URI SANs
are not relevant to IOC access security.

**Why lowercase DNS at extraction time, not passthrough time?**  The EPICS Base SAG
implementation lowercases all SAG entry values at ACF parse time and uses exact string
hash comparison for matching.  Clients must therefore supply lowercase values.  DNS
names are case-insensitive per RFC 4343.  Lowercasing at extraction time ensures that
every downstream consumer — the `Credentials::cred` vector, the `ASSAN` array, and any
log output — always holds consistent lowercase values.  A single normalisation point is
safer than normalising in multiple places.

**Why canonical IP form via `inet_ntop`?**  The raw `GEN_IPADD` data in a certificate
is a 4-byte (IPv4) or 16-byte (IPv6) binary value.  `inet_ntop` always produces the
canonical dotted-decimal IPv4 form (no leading zeros) and the shortest RFC 5952
representation for IPv6 (lowercase hex digits).  EPICS Base SAG uses type-prefixed hash
keys (`"ip:<value>"`) for exact matching; both the ACF entry and the client value must
be in the same canonical form.

**Error handling:**  If `X509_get_ext_d2i` fails (no SAN extension, or malformed), it
returns `nullptr` — the `if` simply does not execute, leaving `cred.san` empty.  This
is identical in behaviour to the pre-SAN case.

### Propagation through the IOC credential pipeline

The IOC `Credentials` class in `ioc/pvxs/credentials.h` gains a matching `san` field
(same `std::vector<SanEntry>` type), and its constructor copies it from
`ClientCredentials`:

```cpp
// In Credentials constructor (ioc/credentials.cpp):
san = src.san;

// Also add SAN values as prefixed cred entries (parallel to "role/..." entries):
for (const auto &s : src.san) {
    if (s.type == "ip")
        cred.push_back("san_ip/" + s.value);
    else if (s.type == "dns")
        cred.push_back("san_dns/" + s.value);
}
```

**The prefixed cred entries provide an immediate, pre-SAG fallback.**  EPICS Base will
not gain SAG support instantaneously.  Operators running against an older EPICS Base
can still write UAG rules that match on SAN values:

```
UAG(subnet_iocs) {
    san_ip/10.0.1.42,
    san_dns/ioc01.slac.stanford.edu
}
```

This follows the established pattern of `role/<rolename>` entries already present in
the cred vector.  The `san_ip/` and `san_dns/` prefixes are unambiguous and unlikely to
collide with real account names (the `/` delimiter is the same convention used by
`role/`).

### Passing SANs to asLib (conditional on EPICS_ASLIB_HAS_SAN)

In `ioc/securityclient.cpp`, `SecurityClient::update()` already constructs an
`ASGIDENTITY` struct and calls `asAddClientIdentity()` when
`EPICS_ASLIB_HAS_IDENTITY` is defined.  We add a second conditional block:

```cpp
#ifdef EPICS_ASLIB_HAS_SAN
    // Build a stack-allocated ASSAN array from Credentials::san.
    // Only "ip" and "dns" types are mapped; unknown types are skipped.
    std::vector<ASSAN> sans;
    sans.reserve(cred->san.size());
    for (const auto &s : cred->san) {
        if (s.type == "ip")
            sans.push_back({asSanIP, s.value.c_str()});
        else if (s.type == "dns")
            sans.push_back({asSanDNS, s.value.c_str()});
    }
    identity.sans  = sans.empty() ? nullptr : sans.data();
    identity.nsans = static_cast<int>(sans.size());
#endif
```

The `ASSAN::value` pointers reference the `std::string` data inside `Credentials::san`
entries.  The `Credentials` object is owned by `SecurityClient` and outlives the
`asAddClientIdentity()` call, so no dangling references arise.

**Why `#ifdef` rather than a runtime version check?**  The `ASGIDENTITY` struct layout
is a compile-time decision.  A runtime check would require knowing the asLib ABI
version at link time, which is not exposed.  This is the same approach used for
`EPICS_ASLIB_HAS_IDENTITY`.  When `EPICS_ASLIB_HAS_SAN` is absent, the `#ifdef` block
compiles away entirely — no dead code, no branch overhead.

**Why not always pass SANs and require EPICS Base to be updated?**  Backwards
compatibility is a first-class concern for a change proposed for upstream inclusion.
Existing EPICS installations running earlier Base versions must continue to compile and
run correctly.

---

## Relationship to the EPICS Base SAG Implementation

The companion EPICS Base change (`aslib-san-access-groups`, commit `41ba1367c` in the
`aslib-san-access-groups` branch of the slac-epics/epics-base fork) provides:

- `EPICS_ASLIB_HAS_SAN` — compile guard in `modules/libcom/src/as/asLib.h`
- `enum asSanType { asSanIP, asSanDNS }` — type discriminator
- `typedef struct { enum asSanType type; const char *value; } ASSAN` — client SAN
  descriptor
- Extended `ASGIDENTITY` with `const ASSAN *sans` and `int nsans`
- ACF grammar extensions (`SAG(name) { IP(...), DNS(...) }`)
- Type-aware matching in `asLibRoutines.c`: exact match for both types; IPv4 CIDR
  subnet for IP entries; glob wildcards for DNS entries; IPv6 exact match
- `LIBCOM_API int asDumpSag(const char *sagname)` — diagnostic dump function

The pvxs mapping is a direct one-to-one translation: `SanEntry::type == "ip"` →
`asSanIP`, `SanEntry::type == "dns"` → `asSanDNS`, `SanEntry::value.c_str()` →
`ASSAN::value`.

---

## Relationship to the PVACMS SAN-in-CCR Implementation

The PVACMS change (`feat/san-in-ccr`, commit `80e8a51` in the slac-epics/pvxs-cms
fork) closes the other end of the pipeline:

- Authentication plugins (std, kerberos, LDAP) accept `--san` / `--server-san` CLI
  flags and corresponding environment variables
- SAN entries are validated (RFC 1035 DNS labels, `inet_pton` IP check) before being
  embedded in the CCR
- `CertFactory` generates the `SubjectAltName` extension from validated entries using
  `GENERAL_NAME_new()` with `GEN_IPADD` (binary, from `inet_pton`) and `GEN_DNS`
  (IA5String)
- The SQLite `certs` table schema was migrated from v3 to v4 to add a `san` column
  (JSON serialised)
- SAN values are replicated in cluster SYNC messages
- `pvxcert status` displays SAN entries alongside the other certificate fields

Without the PVACMS change, certificates will not carry SANs and pvxs will extract an
empty list — entirely safe and backwards-compatible.  The two changes can be deployed
independently.

---

## Access Control — Worked Examples

### Example 1: Subnet-based write restriction (SAG, EPICS Base SAG required)

```
SAG(accelerator_subnet) {
    IP(10.0.1.0/24),
    DNS(*.acc.slac.stanford.edu)
}

ASG(AcceleratorWrite) {
    RULE(1, WRITE) {
        UAG(operators)
        SAG(accelerator_subnet)
    }
    RULE(0, READ) {}
}
```

A PV assigned to `ASG(AcceleratorWrite)` is writable only by a user in `operators`
connecting from a certificate that carries an IP SAN in `10.0.1.0/24` or a DNS SAN
matching `*.acc.slac.stanford.edu`.  This requires EPICS Base built with
`aslib-san-access-groups`.

### Example 2: Exact-host restriction (UAG fallback, any EPICS Base)

```
UAG(trusted_iocs) {
    san_ip/10.0.1.42,
    san_dns/ioc01.slac.stanford.edu
}

ASG(CriticalPV) {
    RULE(1, WRITE) {
        UAG(trusted_iocs)
    }
}
```

This uses the `san_ip/` and `san_dns/` prefixed entries added to the `cred` vector.  It
works with any EPICS Base version and does not require `EPICS_ASLIB_HAS_SAN` to be
defined.  Subnet matching is not available via this path; each IP must be listed
explicitly.

---

## Migration and Rollback

All changes are additive.  The migration path is:

1. **No SANs in existing certificates** → `PeerCredentials::san` is empty; all existing
   behaviour is unchanged.
2. **SANs present, old EPICS Base** → SAN values appear in `Credentials::cred` as
   `san_ip/` and `san_dns/` entries (usable in UAG rules); ASSAN passthrough is
   compiled out.
3. **SANs present, new EPICS Base** → Full SAG support available.

**Rollback** requires only removing the SAN extraction code and struct fields.  There
is no persistent state, no database, and no configuration file to clean up.

---

## Testing

The implementation is covered by `test/testsan.cpp` which exercises:

- A peer certificate with IP and DNS SANs → correct extraction and lowercasing
- IPv6 SAN → canonical RFC 5952 form
- Certificates with `GEN_EMAIL` and `GEN_URI` only → empty `san` vector (skipped)
- Malformed SAN extension → empty `san`, no exception
- `operator<<` output includes `SAN:` line when entries are present; omits it when
  empty
- `Credentials::cred` contains `san_ip/` and `san_dns/` prefixed entries

---

## References

| Resource | Location |
|----------|----------|
| EPICS Base `aslib-san-access-groups` branch | `../epics-base` (slac-epics fork, branch `aslib-san-access-groups`) |
| EPICS Base SAG commit | commit `41ba1367c` — "Add support for SAN Access Groups (SAG) in Access Security" |
| EPICS Base ACF Language doc | `modules/libcom/src/as/ACF-Language.md` |
| EPICS Base `asLib.h` SAG API | `modules/libcom/src/as/asLib.h` |
| PVACMS `feat/san-in-ccr` branch | `../pvxs-cms` (slac-epics fork, branch `feat/san-in-ccr`) |
| PVACMS SAN commit | commit `80e8a51` — "feat: add Subject Alternative Name (SAN) support in certificate creation" |
| pvxs SAN commit | commit `507791ab` — "Add Subject Alternative Name (SAN) extraction and credential support" |
| RFC 5280 §4.2.1.6 | Subject Alternative Name extension definition |
| RFC 4343 | DNS case-insensitivity |
| RFC 5952 | IPv6 address text representation |
| OpenSSL `X509_get_ext_d2i` | SAN extraction API used in `src/openssl.cpp` |
| OpenSpec change | `openspec/changes/san-access-control/` |
