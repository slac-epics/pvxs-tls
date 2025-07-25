/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

/**
 * @file authnstd.h the Standard Authenticator.
 *
 * Provides class to encapsulate the Standard Authenticator and defines custom
 * credentials for use with the authenticator.
 *
 * The Standard authenticator uses the hostname, and the username unless a
 * commandline or environmental configuration is provided.
 *
 * All certificates generated by the Standard authenticator normally require administrator approval
 * before becoming valid.  They are issued in PENDING_APPROVAL status.  An administrator must use the
 * PUT request to the status PV included as an extension in the certificate to approve the certificate.
 */

#ifndef PVXS_AUTH_DEFAULT_H
#define PVXS_AUTH_DEFAULT_H

#include <functional>
#include <memory>
#include <string>

#include <pvxs/data.h>
#include <pvxs/version.h>

#include "auth.h"
#include "authregistry.h"
#include "certfactory.h"
#include "configstd.h"
#include "ownedptr.h"
#include "security.h"

#define PVXS_X509_AUTH_DEFAULT_VALIDITY_S (static_cast<time_t>(365.25 * 24 * 60 * 60) / 2)  // Half a year
#define PVXS_X509_AUTH_HOSTNAME_MAX 1024
#define PVXS_X509_AUTH_USERNAME_MAX 256

namespace pvxs {
namespace certs {

/**
 * The subclass of Credentials that contains the AuthNStd specific
 * identification object
 */
struct DefaultCredentials final : Credentials {};

class AuthNStd final : public Auth {
   public:
    // Constructor
    AuthNStd() : Auth(PVXS_DEFAULT_AUTH_TYPE, {}) {}
    ~AuthNStd() override = default;

    std::shared_ptr<Credentials> getCredentials(const client::Config &config, bool for_client) const override;

    std::shared_ptr<CertCreationRequest> createCertCreationRequest(const std::shared_ptr<Credentials> &credentials,
                                                                 const std::shared_ptr<KeyPair> &key_pair,
                                                                 const uint16_t &usage,
                                                                 const ConfigAuthN &config) const override;

    bool verify(Value &ccr, time_t &authenticated_expiration_date) const override;

    void fromEnv(std::unique_ptr<client::Config> &config) override { config.reset(new ConfigStd(ConfigStd::fromEnv())); }
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_AUTH_DEFAULT_H
