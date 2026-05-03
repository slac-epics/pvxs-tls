/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "peerstatusstore.h"

#include <ctime>
#include <utility>

#include <pvxs/log.h>

#include "certstatus.h"

namespace pvxs {
namespace ossl {

DEFINE_LOGGER(store, "pvxs.tls.psstore");

PeerCertId peerCertIdFromX509(X509* cert) noexcept {
    if (!cert) return {};
    try {
        return certs::CertStatusManager::getCertIdFromCert(cert);
    } catch (const std::exception& e) {
        log_debug_printf(store, "peerCertIdFromX509: %s\n", e.what());
        return {};
    }
}

PeerStatusStore& PeerStatusStore::instance() noexcept {
    static PeerStatusStore inst;
    return inst;
}

std::shared_ptr<const certs::CertificateStatus>
PeerStatusStore::lookup(const PeerCertId& id) const {
    if (id.empty()) return {};
    Guard G(lock_);
    const auto it = entries_.find(id);
    if (it == entries_.end()) return {};

    const auto& entry = it->second;
    if (!entry) {
        entries_.erase(it);
        return {};
    }
    if (!entry->isPermanent() && !entry->isStatusCurrent()) {
        log_debug_printf(store, "lookup(%s): expired entry evicted\n", id.c_str());
        entries_.erase(it);
        return {};
    }
    return entry;
}

std::pair<bool, certs::cert_status_class_t>
PeerStatusStore::update(const PeerCertId& id, const certs::CertificateStatus& status) {
    if (id.empty()) return {false, certs::cert_status_class_t::UNKNOWN};
    Guard G(lock_);
    bool had_prior = false;
    auto prior_class = certs::cert_status_class_t::UNKNOWN;
    const auto it = entries_.find(id);
    if (it != entries_.end() && it->second) {
        had_prior = true;
        prior_class = it->second->getStatusClass();
    }
    entries_[id] = std::make_shared<certs::CertificateStatus>(status);
    log_debug_printf(store, "update(%s): %s -> %s%s\n",
                     id.c_str(),
                     had_prior ? status.status.s.c_str() : "(none)",
                     status.status.s.c_str(),
                     had_prior ? "" : " (new)");
    return {had_prior, prior_class};
}

void PeerStatusStore::recordGuidBinding(const ServerGUID& guid, const PeerCertId& id) {
    if (id.empty()) return;
    Guard G(lock_);
    guid_bindings_[guid] = id;
}

bool PeerStatusStore::lookupByGuid(const ServerGUID& guid, PeerCertId& out) const {
    Guard G(lock_);
    const auto it = guid_bindings_.find(guid);
    if (it == guid_bindings_.end()) return false;
    out = it->second;
    return true;
}

PeerStatusStore::ObserverHandle
PeerStatusStore::registerRecoveryObserver(std::function<void(const PeerCertId&)> fn) {
    Guard G(lock_);
    const auto handle = next_handle_++;
    observers_.emplace_back(handle, std::move(fn));
    return handle;
}

void PeerStatusStore::unregisterRecoveryObserver(ObserverHandle handle) {
    Guard G(lock_);
    for (auto it = observers_.begin(); it != observers_.end(); ++it) {
        if (it->first == handle) {
            observers_.erase(it);
            return;
        }
    }
}

void PeerStatusStore::fireRecoveryObservers(const PeerCertId& id) {
    std::vector<std::function<void(const PeerCertId&)>> snapshot;
    {
        Guard G(lock_);
        snapshot.reserve(observers_.size());
        for (const auto& slot : observers_) {
            snapshot.push_back(slot.second);
        }
    }
    for (auto& fn : snapshot) {
        try {
            fn(id);
        } catch (const std::exception& e) {
            log_warn_printf(store, "recovery observer threw: %s\n", e.what());
        }
    }
}

void PeerStatusStore::reset() {
    Guard G(lock_);
    entries_.clear();
    guid_bindings_.clear();
    observers_.clear();
    next_handle_ = 1;
}

}  // namespace ossl
}  // namespace pvxs
