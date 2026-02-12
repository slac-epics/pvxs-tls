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
