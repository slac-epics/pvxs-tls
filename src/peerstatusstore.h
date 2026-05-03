/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */
#ifndef PVXS_PEERSTATUSSTORE_H
#define PVXS_PEERSTATUSSTORE_H

#include <cstddef>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <epicsAssert.h>
#include <epicsMutex.h>

#include <openssl/x509.h>

#include <pvxs/util.h>

#include "certstatus.h"

namespace pvxs {
namespace ossl {

/**
 * @brief Identity of a peer certificate, used as the key in PeerStatusStore.
 *
 * Currently a `std::string` of the form "{issuer_8hex}:{serial_20decimal}",
 * matching the shape produced by `pvxs::certs::CertStatusManager::getCertIdFromCert()`
 * and the existing on-disk OCSP cache key. Wrapping this in a typedef rather
 * than exposing `std::string` directly so we can swap to a structured key
 * (issuer hash + serial integer) without touching call sites.
 *
 * @since UNRELEASED
 */
using PeerCertId = std::string;

/**
 * @brief Compute the canonical PeerCertId from an X509 certificate.
 *
 * Single source of truth for peer cert identity. All consumer/update sites
 * that touch `PeerStatusStore` MUST derive their key through this helper to
 * guarantee key consistency.
 *
 * Returns an empty string and logs at debug if the cert lacks the AKID
 * extension required by `getIssuerIdFromCert` (peer certs without the SPVA
 * status extension simply cannot participate in the peer-status store).
 *
 * @since UNRELEASED
 */
PVXS_API PeerCertId peerCertIdFromX509(X509* cert) noexcept;

/**
 * @brief Process-wide singleton store of peer cert status entries.
 *
 * Holds STRONG references to the most recently delivered `CertificateStatus`
 * for each peer cert seen by any `Connection` / `ServerConn` in the process.
 * Survives every disconnect; entries expire only when the cert's PVACMS-signed
 * `status_valid_until_date` passes (consulted at lookup time).
 *
 * Function-local-static (Meyers) singleton: C++11 thread-safe initialization,
 * no global constructor (complies with `pvxs/AGENTS.md`).
 *
 * @since UNRELEASED
 */
class PVXS_API PeerStatusStore {
public:
    /**
     * @brief Acquire the process-wide singleton.
     *
     * Function-local static. First call constructs; all subsequent calls
     * return the same instance. Thread-safe per C++11 [stmt.dcl]/4.
     */
    static PeerStatusStore& instance() noexcept;

    /**
     * @brief Look up the cached status for a peer.
     *
     * Returns the cached entry if present AND the entry's
     * `status_valid_until_date` is still in the future. If the entry has
     * expired, it is removed and an empty pointer is returned.
     *
     * @param id peer cert identity (typically from `peerCertIdFromX509`)
     * @return shared_ptr to the cached status, or empty if absent/expired
     */
    std::shared_ptr<const certs::CertificateStatus> lookup(const PeerCertId& id) const;

    /**
     * @brief Insert or overwrite the cached status for a peer.
     *
     * Always overwrites: the latest delivery is authoritative.
     *
     * @param id peer cert identity
     * @param status fresh status delivery
     * @return the prior entry's status class, or empty if there was no prior entry.
     *         Used by recovery-observer logic (D10) to detect non-GOOD->GOOD
     *         transitions without spurious teardowns on GOOD->GOOD churn.
     */
    std::pair<bool, certs::cert_status_class_t>
        update(const PeerCertId& id, const certs::CertificateStatus& status);

    /**
     * @brief Record the binding from a server's GUID to its cert identity.
     *
     * Populated whenever a successful TLS handshake (client or server side)
     * has both the server GUID and the peer cert in hand. Subsequent SEARCH
     * replies (which carry GUID but not the cert itself) can then resolve
     * to the cached status via `lookupByGuid`.
     */
    void recordGuidBinding(const ServerGUID& guid, const PeerCertId& id);

    /**
     * @brief Resolve a server GUID to a PeerCertId via the auxiliary map.
     *
     * @param guid server GUID from a SEARCH reply or beacon
     * @param out filled in with the bound PeerCertId on success
     * @return true if the binding was found, false otherwise
     */
    bool lookupByGuid(const ServerGUID& guid, PeerCertId& out) const;

    /**
     * @brief Recovery-observer registration handle.
     *
     * Returned from `registerRecoveryObserver`; opaque to callers but used
     * by `unregisterRecoveryObserver` to identify the slot to remove
     * without comparing function pointers (which is unreliable for lambdas).
     */
    using ObserverHandle = std::size_t;

    /**
     * @brief Register a callback fired when a peer recovers from non-GOOD to GOOD.
     *
     * The callback is invoked OUTSIDE the store's lock to avoid deadlocks
     * with observers that re-enter the store. Observers SHOULD post work to
     * their own event loop rather than do real work on the calling thread.
     *
     * @param fn observer callback receiving the recovered peer's id
     * @return handle for `unregisterRecoveryObserver`
     */
    ObserverHandle registerRecoveryObserver(std::function<void(const PeerCertId&)> fn);

    /**
     * @brief Unregister a previously registered observer.
     *
     * Safe to call from any thread. If `handle` is unknown, the call is a no-op.
     */
    void unregisterRecoveryObserver(ObserverHandle handle);

    /**
     * @brief Fire all registered observers with the given peer id.
     *
     * Called from the peer-status delivery callback when `update()` returned
     * a non-GOOD prior class and the new class is GOOD. Observers are invoked
     * sequentially with the lock RELEASED.
     */
    void fireRecoveryObservers(const PeerCertId& id);

    /**
     * @brief TEST-ONLY: clear all entries, bindings, and observers.
     *
     * Compiled in regardless of build flags (see notes in implementation)
     * because the test binary links against the same library object as
     * production code; gating this with `#ifdef PVXS_UNITTEST` would require
     * a separate build of the library. The cost is one exported symbol; the
     * function is harmless in production (only callable explicitly).
     */
    void reset();

private:
    PeerStatusStore() = default;
    PeerStatusStore(const PeerStatusStore&) = delete;
    PeerStatusStore& operator=(const PeerStatusStore&) = delete;

    mutable epicsMutex lock_;
    mutable std::map<PeerCertId, std::shared_ptr<certs::CertificateStatus>> entries_;
    std::map<ServerGUID, PeerCertId> guid_bindings_;

    ObserverHandle next_handle_{1};
    std::vector<std::pair<ObserverHandle, std::function<void(const PeerCertId&)>>> observers_;
};

}  // namespace ossl
}  // namespace pvxs

#endif  // PVXS_PEERSTATUSSTORE_H
