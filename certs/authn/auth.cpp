/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "auth.h"

#include <iostream>
#include <memory>
#include <string>

#include <pvxs/log.h>

#include "authregistry.h"
#include "ccrmanager.h"
#include "certfactory.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"

DEFINE_LOGGER(config, "pvxs.auth.config");

namespace pvxs {
namespace certs {

/**
 * @brief Get a pointer to the singleton Auth object for the given type.
 *
 * This function returns a pointer to the singleton Auth object for the given type.
 *
 * @param type the type of the Auth object to get (e.g. "std", "ldap", "krb", "jwt")
 * @return a pointer to the singleton Auth object for the given type
 * @throws std::logic_error if the Auth object for the given type is not found
 */
Auth *Auth::getAuth(const std::string &type) {
    const auto auth = AuthRegistry::instance().getAuth(type);
    if (auth == nullptr) {
        throw std::logic_error("Auth::getAuth: no such auth type");
    }
    return auth;
}

/**
 * @brief Creates a signed certificate.
 *
 * Create a PVStructure that corresponds to the ccr parameter of a certificate
 * creation request. This request will be sent to the PVACMS through the default
 * channel (PVAccess) and will be used to create the certificate.
 *
 * @param credentials the credentials that describe the subject of the
 * certificate
 * @param key_pair the public/private key to be used in the certificate, only
 * public key is used
 * @param usage the desired certificate usage
 * @param config The configuration for the certificate
 * @return A managed shared CertCreationRequest object.
 */
std::shared_ptr<CertCreationRequest> Auth::createCertCreationRequest(const std::shared_ptr<Credentials> &credentials, const std::shared_ptr<KeyPair> &key_pair,
                                                                     const uint16_t &usage, const ConfigAuthN &config) const {
    // Create a new CertCreationRequest object.
    auto cert_creation_request = std::make_shared<CertCreationRequest>(type_, verifier_fields_);
    cert_creation_request->credentials = credentials;

    // Fill in the ccr from the base data we've gathered so far.
    if (key_pair) {
        cert_creation_request->ccr["type"] = type_; // Authenticator type
        cert_creation_request->ccr["usage"] = usage; // Desired Certificate usage
        cert_creation_request->ccr["pub_key"] = key_pair->public_key; // The public key to use (you keep the private key private)

        // Optional CCR components
        if (!credentials->name.empty()) cert_creation_request->ccr["name"] = credentials->name;
        if (!credentials->organization.empty()) cert_creation_request->ccr["organization"] = credentials->organization;
        if (!credentials->organization_unit.empty()) cert_creation_request->ccr["organization_unit"] = credentials->organization_unit;
        if (!credentials->country.empty()) cert_creation_request->ccr["country"] = credentials->country;
        if (credentials->not_before >0) cert_creation_request->ccr["not_before"] = credentials->not_before;
        if (credentials->not_after >0) cert_creation_request->ccr["not_after"] = credentials->not_after;

        // Don't include any status checking extension.  This will disable any certificate renewal functionality
        if (config.no_status) cert_creation_request->ccr["no_status"] = config.no_status;

        // Do we need to add a configuration uri to the certificate?
        if (!credentials->config_uri_base.empty()) cert_creation_request->ccr["config_uri_base"] = credentials->config_uri_base;
    }
    return cert_creation_request;
}

/**
 * @brief Signs a certificate.
 *
 * This function takes a certificate creation request and sends its ccr
 * PVStructure to PVACMS to be signed. It will wait for the signed signature or
 * any reported error.
 *
 * @param ccr A shared pointer to a CertCreationRequest object
 * containing the ccr PVStructure which contains the certificate, and its
 * validity as well as any verifier specific required fields.
 * @param timeout the timeout for the request
 * @param cert_pv_prefix the CMS pv prefix
 * @param issuer_id the issuer ID of the CMS
 * @return the certificate in PEM format with the certificate authority chain ordered from leaf to root
 * @throws std::runtime_error when exceptions arise
 *
 * @note It is the responsibility of the caller to ensure that the
 * CCR object is valid and contains the required information
 * before calling this function.
 */
std::string Auth::processCertificateCreationRequest(const std::shared_ptr<CertCreationRequest> &ccr, const std::string &cert_pv_prefix, const std::string &issuer_id, const double timeout) const {
    // Forward the ccr to the certificate management service
    return ccr_manager_.createCertificate(ccr, cert_pv_prefix, issuer_id, timeout);
}

/**
 * @brief Run the authenticator daemon
 *
 * This Authenticator daemon will re-run the Authenticator each time the
 * certificate expires to try to get another certificate.  It will also
 * maintain a PV that will publish the current status and how much time there is
 * remaining until the current certificate expires.
 *
 * Clients will automatically reconfigure connections when certs expire, so if a new
 * certificate is available, then it will be picked up automatically.
 *
 * @param authn_config The Authenticator's configuration
 * @param for_client Whether the daemon is for a client or server
 * @param cert_data The certificate data (contains cert, cert_auth_chain, and key)
 * @param fn The function to call to get the next certificate
 */
void Auth::runAuthNDaemon(const ConfigAuthN &authn_config, bool for_client, CertData &&cert_data, const std::function<CertData()> &&fn) {
    auto issuer_id = CertStatus::getIssuerId(cert_data.cert_auth_chain);
    const std::string skid(CertStatus::getSkId(cert_data.cert));

    // Create a ConfigMonitorParams object to pass to the configuration monitor
    auto config_monitor_params = std::make_shared<ConfigMonitorParams>(authn_config, cert_data.cert, std::move(fn));

    // Server Mailbox configuration with disabled tls
    const auto config = server::Config::fromEnv(true);
    server::SharedPV config_pv(server::SharedPV::buildMailbox());
    config_pv.open(config_monitor_params->config_pv_value);

    // Create a server with a custom timer event that runs our configuration monitor
    config_server_ = server::Server(config, [config_monitor_params, &config_pv](short) { return configurationMonitor(config_monitor_params, config_pv); });

    config_pv.onFirstConnect([&config_monitor_params, &for_client, &authn_config, &issuer_id](server::SharedPV &pv) {
        const auto serial = CertStatusFactory::getSerialNumber(config_monitor_params->cert_);

        // Check the amount of time before the certificate expires or the renew_by date
        const CertDate expiry_date = X509_get_notAfter(config_monitor_params->cert_.get());
        CertDate renew_by = expiry_date;
        try {
            renew_by = CertStatusManager::getRenewByFromCert(config_monitor_params->cert_);
        } catch (...) {}
        const std::string renew_by_s = std::ctime(&renew_by.t);

        setValue<std::string>(config_monitor_params->config_pv_value, "issuer_id", issuer_id);
        setValue<std::string>(config_monitor_params->config_pv_value, "keychain", for_client ? authn_config.tls_keychain_file : authn_config.tls_srv_keychain_file);
        setValue<uint64_t>(config_monitor_params->config_pv_value, "serial", serial);
        setValue<std::string>(config_monitor_params->config_pv_value, "renewal_date", renew_by_s.substr(0, renew_by_s.size()-1));

        pv.post(config_monitor_params->config_pv_value);
    });

    config_pv.onLastDisconnect([](server::SharedPV &pv) { pv.close(); });

    // Run the CONFIG server
    const std::string pv_name = getConfigURI(authn_config.cert_pv_prefix, issuer_id, skid);
    config_server_.addPV(pv_name, config_pv);
    std::cout << "Cert Config info available on: " << pv_name << std::endl;
    config_server_.run();
}

/**
 * @brief Run the configuration monitor
 *
 * This runs each time the certificate expires (except first time runs after 15 seconds).
 *   - Check if cert has expired (normally it will have except first time)
 *   - If it has not yet expired then calculate remaining time and then reschedule wakeup
 *   - If it has expired
 *     -
 *
 * @param config_monitor_params
 * @param pv
 * @return
 */
timeval Auth::configurationMonitor(std::shared_ptr<ConfigMonitorParams> config_monitor_params, server::SharedPV &pv) {
    // Check time before the certificate renewal
    const time_t now = time(nullptr);
    const CertDate expiry_date = X509_get_notAfter(config_monitor_params->cert_.get());
    CertDate renew_by = expiry_date;
    try {
        renew_by = CertStatusManager::getRenewByFromCert(config_monitor_params->cert_);
    } catch (...) {}
    time_t expires_in = renew_by.t - now - CERT_RENEWAL_LEAD_TIME;

    // If the timer has not yet expired
    if (expires_in > 0) {
        // Set time interval for next callback and return
        return {expires_in, 0};
    }

    // If timer has expired call function to update config with a new certificate
    try {
        config_monitor_params->cert_ = config_monitor_params->fn_().cert;
        // Reset adaptive timeout
        config_monitor_params->adaptive_timeout_mins_ = 0;
    } catch (const std::exception &e) {
        // Stop if we're already at the max retries
        if (config_monitor_params->adaptive_timeout_mins_ == PVXS_CONFIG_MONITOR_TIMEOUT_MAX) return {};

        config_monitor_params->adaptive_timeout_mins_ =
            !config_monitor_params->adaptive_timeout_mins_ ? 1 : std::min(config_monitor_params->adaptive_timeout_mins_ * 2, PVXS_CONFIG_MONITOR_TIMEOUT_MAX);
        log_err_printf(config, "Config refresh error.  Retry in %d mins: %s\n", config_monitor_params->adaptive_timeout_mins_, e.what());
        return {config_monitor_params->adaptive_timeout_mins_ * 60, 0};
    }

    // Compute next expiry time and post an update with the new serial number
    const CertDate new_expiry_date = X509_get_notAfter(config_monitor_params->cert_.get());
    CertDate new_renew_by = new_expiry_date;
    try {
        new_renew_by = CertStatusManager::getRenewByFromCert(config_monitor_params->cert_);
    } catch (...) {}
    expires_in = new_renew_by.t - now - CERT_RENEWAL_LEAD_TIME;
    const std::string new_renew_by_s = std::ctime(&new_renew_by.t);

    if ( new_renew_by.t > now ) {
        // If renewal is in future then post updated time
        pv.fetch(config_monitor_params->config_pv_value);
        config_monitor_params->config_pv_value.unmark(true, true);
        setValue<uint64_t>(config_monitor_params->config_pv_value, "serial", CertStatusFactory::getSerialNumber(config_monitor_params->cert_));
        setValue<std::string>(config_monitor_params->config_pv_value, "renewal_date", new_renew_by_s.substr(0, new_renew_by_s.size()-1));
        pv.post(config_monitor_params->config_pv_value);
    }

    if (expires_in < 0) expires_in = CERT_RENEWAL_LEAD_TIME;

    // Call back when expired
    return {expires_in, 0};
}

std::string Auth::formatTimeDuration(time_t total_seconds) {
    // Calculate days, hours, minutes, and seconds.
    constexpr time_t seconds_per_day = 86400;
    constexpr time_t seconds_per_hour = 3600;
    constexpr time_t seconds_per_minute = 60;

    const time_t days = total_seconds / seconds_per_day;
    total_seconds %= seconds_per_day;
    const time_t hours = total_seconds / seconds_per_hour;
    total_seconds %= seconds_per_hour;
    const time_t minutes = total_seconds / seconds_per_minute;
    const time_t secs = total_seconds % seconds_per_minute;

    // Build a vector of non-optional parts.
    // According to the format, the days, hrs, and mins parts are only included if nonzero.
    // Seconds are always displayed.
    std::vector<std::string> parts;
    if (days > 0) {
        parts.push_back(std::to_string(days) + " days");
    }
    if (hours > 0) {
        parts.push_back(std::to_string(hours) + " hrs");
    }
    if (minutes > 0) {
        parts.push_back(std::to_string(minutes) + " mins");
    }
    if (parts.empty() || secs > 0) {
        parts.push_back(std::to_string(secs) + " secs");
    }

    // Join the parts using the pattern:
    //  - If only one part exists, return it.
    //  - If two parts exist, join with " and ".
    //  - If three or more parts exist, join with commas, but use " and " before the last part.
    std::ostringstream oss;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            if (i == parts.size() - 1) {
                oss << " and ";
            } else {
                oss << ", ";
            }
        }
        oss << parts[i];
    }
    return oss.str();
}


}  // namespace certs
}  // namespace pvxs
