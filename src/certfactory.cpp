/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certfactory.h"

#include <limits>
#include <memory>
#include <string>
#include <type_traits>
#include <unordered_set>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <pvxs/config.h>
#include <pvxs/log.h>

#include "openssl.h"
#include "opensslgbl.h"
#include "osiFileName.h"
#include "ownedptr.h"
#include "security.h"
#include "utilpvt.h"

namespace pvxs {
namespace certs {

DEFINE_LOGGER(certs, "pvxs.certs.cms");

/**
 * @brief HELPER FUNCTION: Create a new managed Basic Input Output
 * object that can be used to output in various forms, throw for errors
 *
 * @return new managed BIO object
 */
ossl_ptr<BIO> CertFactory::newBio() {
    ERR_clear_error();
    ossl_ptr<BIO> bio(BIO_new(BIO_s_mem()), false);
    if (!bio) {
        throw std::runtime_error(SB() << "Error: Failed to create bio for output: " << getError());
    }
    return bio;
}

/**
 * HELPER FUNCTION: Add the given certificate to the given Basic Input Output
 * object
 *
 * @param bio the BIO to add the cert to
 * @param cert the certificate to add to the BIO stream
 */
void CertFactory::writeCertToBio(const ossl_ptr<BIO> &bio, const ossl_ptr<X509> &cert) {
    ERR_clear_error();
    if (!PEM_write_bio_X509(bio.get(), cert.get())) {
        throw std::runtime_error(SB() << "Error writing certificate to BIO: " << getError());
    }
}

/**
 * HELPER FUNCTION: Add the given certificate stack to the given Basic Input
 * Output object
 *
 * @param bio the BIO to add the cert to
 * @param chain the certificate stack to add to the BIO stream
 */
void CertFactory::writeCertsToBio(const ossl_ptr<BIO> &bio, const STACK_OF(X509) * chain) {
    if (chain) {
        ERR_clear_error();
        // Get the number of certificates in the stack
        const int count = sk_X509_num(chain);

        for (int i = 0; i < count; i++) {
            if (!PEM_write_bio_X509(bio.get(), sk_X509_value(chain, i))) {
                log_err_printf(certs, "STACK ERROR: %s\n", getError().c_str());
                throw std::runtime_error(SB() << "Error writing certificate to BIO: " << getError());
            }
        }
    }
}

time_t CertFactory::getNotAfterTimeFromCert(const ossl_ptr<X509> &cert) {
    const ASN1_TIME *cert_not_after = X509_get_notAfter(cert.get());
    const time_t not_after = CertDate::asn1TimeToTimeT(cert_not_after);
    return not_after;
}

void CertFactory::set_skid(const ossl_ptr<X509> &certificate) {
    int pos = -1;
    std::stringstream skid_ss;

    pos = X509_get_ext_by_NID(certificate.get(), NID_subject_key_identifier, pos);
    X509_EXTENSION *ex = X509_get_ext(certificate.get(), pos);

    const ossl_ptr<ASN1_OCTET_STRING> skid(static_cast<ASN1_OCTET_STRING *>(X509V3_EXT_d2i(ex)), false);

    if (skid != nullptr) {
        // Convert to hexadecimal string
        for (int i = 0; i < skid->length; i++) {
            skid_ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(skid->data[i]);
        }
    }

    skid_ = skid_ss.str();
}

}  // namespace certs
}  // namespace pvxs
