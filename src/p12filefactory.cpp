/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include <climits>
#include <cstdio>
#include <memory>

#include <libgen.h>

#ifdef __unix__
#include <pwd.h>
#endif
#include <string>
#include <tuple>
#include <type_traits>
#include <unordered_set>

#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "certfactory.h"
#include "openssl.h"
#include "osiFileName.h"
#include "ownedptr.h"
#include "p12filefactory.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(filelogger, "pvxs.p12");

/**
 * @brief Get a key pair from a P12 file
 *
 * @return a shared pointer to the KeyPair object
 * @throw std::runtime_error if the file cannot be opened
 * @throw ossl::SSLError if file cannot be parsed
 */
std::shared_ptr<KeyPair> P12FileFactory::getKeyFromFile() {
    const file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error getting private key from file: \"" << filename_ << "\": " << strerror(errno));
    }

    const ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr), false);
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening private key file as a PKCS#12 object: " << filename_);
    }

    ossl_ptr<EVP_PKEY> pkey;
    if (!PKCS12_parse(p12.get(), password_.c_str(), pkey.acquire(), nullptr, nullptr)) {
        throw ossl::SSLError(SB() << "Error parsing private key file: " << filename_);
    }

    return std::make_shared<KeyPair>(std::move(pkey));
}

/**
 * @brief Get the certificate data from a P12 file
 *
 * The P12 file is parsed to extract the certificate and chain.
 * If it contains a private key too then it is read and returned in the CertData object.
 *
 * @return a CertData object
 * @throw std::runtime_error if the file cannot be opened or parsed
 */
CertData P12FileFactory::getCertDataFromFile() {
    ossl_ptr<X509> cert;
    ossl_ptr<STACK_OF(X509)> chain(sk_X509_new_null(), false);
    std::shared_ptr<KeyPair> key_pair;
    ossl_ptr<EVP_PKEY> pkey;

    // Get cert from configured file
    const file_ptr fp(fopen(filename_.c_str(), "rb"), false);
    if (!fp) {
        throw std::runtime_error(SB() << "Error opening keychain file for reading binary contents: \"" << filename_ << "\"");
    }

    const ossl_ptr<PKCS12> p12(d2i_PKCS12_fp(fp.get(), nullptr), false);
    if (!p12) {
        throw std::runtime_error(SB() << "Error opening keychain file as a PKCS#12 object: " << filename_);
    }

    // Try to get private key and certificates
    if (!PKCS12_parse(p12.get(), password_.c_str(), pkey.acquire(), cert.acquire(), chain.acquire())) {
        throw std::runtime_error(SB() << "Error parsing keychain file: " << filename_);
    }

    if (!!cert ^ !!pkey) {
        log_warn_printf(filelogger, "Inconsistency between certificate and key: %s\n", filename_.c_str());
        cert.reset();
        pkey.reset();
    }

    if (!chain) {
        chain.reset(sk_X509_new_null());
    }
    // If no certificate authority certificate chain was provided, then check if the entity cert is self-signed.
    // If it is, add it as a single-entry chain.
    if (!chain || sk_X509_num(chain.get()) == 0) {
        if (cert && X509_check_issued(cert.get(), cert.get()) == X509_V_OK) {
            if (!sk_X509_push(chain.get(), X509_dup(cert.get()))) {
                throw std::runtime_error("Error adding self-signed certificate to chain");
            }
        }
    }

    ossl_shared_ptr<STACK_OF(X509)> shared_chain(std::move(chain));

    return {cert, shared_chain, (pkey ? std::make_shared<KeyPair>(std::move(pkey)) : nullptr)};
}

#ifdef NID_oracle_jdk_trustedkeyusage
    /**
     * @brief Add the JDK trusted key usage attribute to the p12 object
     *
     * This is done by using the callback mechanism that is triggered by PKCS12_create_ex2 for every bag.
     * We can then ignore all bags except X509 certificates with an associated key.
     *
     * This is conditionally compiled in for platforms that support it.
     *
     * @param bag the p12 safe bag to add the attribute to
     * @return 1 if the attribute was added, 0 if it was not added
     */
    int P12FileFactory::jdkTrust(PKCS12_SAFEBAG *bag, void *) noexcept {
        try {
            // Only add trustedkeyusage when bag is an X509 cert. with an
            // associated key (when localKeyID is present) which does not
            // already have trustedkeyusage.
            if (PKCS12_SAFEBAG_get_nid(bag) != NID_certBag || PKCS12_SAFEBAG_get_bag_nid(bag) != NID_x509Certificate ||
                !!PKCS12_SAFEBAG_get0_attr(bag, NID_localKeyID) || !!PKCS12_SAFEBAG_get0_attr(bag, NID_oracle_jdk_trustedkeyusage))
                return 1;

            const auto curattrs(PKCS12_SAFEBAG_get0_attrs(bag));
            pvxs::ossl_ptr<STACK_OF(X509_ATTRIBUTE)> newattrs(sk_X509_ATTRIBUTE_deep_copy(curattrs, &X509_ATTRIBUTE_dup, &X509_ATTRIBUTE_free));

            const ossl_ptr<ASN1_OBJECT> trust(OBJ_txt2obj("anyExtendedKeyUsage", 0));
            ossl_ptr<X509_ATTRIBUTE> attr(X509_ATTRIBUTE_create(NID_oracle_jdk_trustedkeyusage, V_ASN1_OBJECT, trust.get()));

            if (sk_X509_ATTRIBUTE_push(newattrs.get(), attr.get()) != 1) {
                log_err_printf(filelogger, "Unable to add JDK trust attribute%s\n", "");
                return 1;
            }
            attr.release();

            PKCS12_SAFEBAG_set0_attrs(bag, newattrs.get());
            newattrs.release();

            return 1;
        } catch (std::exception &e) {
            log_err_printf(filelogger, "Unable to add JDK trust attribute: %s\n", e.what());
            return 0;
        }
    }
#endif

}  // namespace certs
}  // namespace pvxs
