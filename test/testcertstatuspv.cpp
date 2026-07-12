/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

// Exception classification for getStatusPvFromCert() / getCertIdFromCert().
#define PVXS_ENABLE_EXPERT_API

#include <string>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>

#include <epicsUnitTest.h>
#include <testMain.h>

#include <pvxs/unittest.h>

#include "certstatus.h"
#include "opensslgbl.h"
#include "ownedptr.h"

namespace {

using namespace pvxs;
using pvxs::certs::CertStatusManager;
using pvxs::certs::CertStatusNoExtensionException;
using pvxs::certs::CertStatusExtensionDecodeException;
using pvxs::certs::CertStatusIdException;

// Minimal self-signed X509 (no status extension, no AKID).
ossl_ptr<X509> makeBareCert() {
    ossl_ptr<EVP_PKEY> key(EVP_RSA_gen(2048));
    if (!key) throw std::runtime_error("EVP_RSA_gen failed");

    ossl_ptr<X509> cert(X509_new());
    if (!cert) throw std::runtime_error("X509_new failed");
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 12345);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60 * 60);

    auto* name = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("testcertstatuspv"), -1, -1, 0);
    X509_set_issuer_name(cert.get(), name);  // self-signed
    X509_set_pubkey(cert.get(), key.get());
    if (!X509_sign(cert.get(), key.get(), EVP_sha256()))
        throw std::runtime_error("X509_sign failed");
    return cert;
}

// Status-PV extension with a raw octet-string payload (valid DER IA5String
// decodes; arbitrary bytes do not).
void addRawStatusExtension(X509* cert, const std::string& payload) {
    ossl_ptr<ASN1_OCTET_STRING> oct(ASN1_OCTET_STRING_new());
    ASN1_OCTET_STRING_set(oct.get(),
                          reinterpret_cast<const unsigned char*>(payload.data()),
                          static_cast<int>(payload.size()));
    ossl_ptr<X509_EXTENSION> ext(
        X509_EXTENSION_create_by_NID(nullptr, ossl::NID_SPvaCertStatusURI, 0, oct.get()), false);
    if (!ext) throw std::runtime_error("X509_EXTENSION_create_by_NID failed");
    if (!X509_add_ext(cert, ext.get(), -1)) throw std::runtime_error("X509_add_ext failed");
}

// DER-encode a string as an IA5String (the valid on-the-wire form).
std::string derIA5(const std::string& s) {
    ossl_ptr<ASN1_IA5STRING> ia5(ASN1_IA5STRING_new());
    ASN1_STRING_set(ia5.get(), s.data(), static_cast<int>(s.size()));
    unsigned char* der = nullptr;
    const int len = i2d_ASN1_IA5STRING(ia5.get(), &der);
    ossl_ptr<unsigned char> hold(der);
    if (len < 0) throw std::runtime_error("i2d_ASN1_IA5STRING failed");
    return {reinterpret_cast<char*>(der), static_cast<size_t>(len)};
}

// Add an Authority Key Identifier extension so getCertIdFromCert() can derive an
// issuer id. makeBareCert() deliberately omits the AKID (an optional extension),
// which is why a bare cert triggers CertStatusIdException.
void addAkid(X509* cert) {
    ossl_ptr<ASN1_OCTET_STRING> keyid(ASN1_OCTET_STRING_new());
    static const unsigned char id[] = {0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04};
    ASN1_OCTET_STRING_set(keyid.get(), id, sizeof(id));
    ossl_ptr<AUTHORITY_KEYID> akid(AUTHORITY_KEYID_new());
    akid->keyid = keyid.release();  // AUTHORITY_KEYID takes ownership
    if (!X509_add1_ext_i2d(cert, NID_authority_key_identifier, akid.get(), 0, 0))
        throw std::runtime_error("X509_add1_ext_i2d(AKID) failed");
}

}  // namespace

MAIN(testcertstatuspv)
{
    testPlan(5);

    ossl::osslInit();  // registers NID_SPvaCertStatusURI

    // (a) No status extension -> CertStatusNoExtensionException
    {
        const auto cert = makeBareCert();
        testThrows<CertStatusNoExtensionException>([&]() {
            (void)CertStatusManager::getStatusPvFromCert(cert.get());
        });
    }

    // (b) Present + decodable
    {
        const auto cert = makeBareCert();
        const std::string pv("anything:the:issuer:likes");
        addRawStatusExtension(cert.get(), derIA5(pv));
        testEq(CertStatusManager::getStatusPvFromCert(cert.get()), pv);
    }

    // (c) Present + undecodable (not a valid DER IA5String) -> CertStatusExtensionDecodeException
    {
        const auto cert = makeBareCert();
        addRawStatusExtension(cert.get(), std::string("\xff\xff\xff not DER", 12));
        testThrows<CertStatusExtensionDecodeException>([&]() {
            (void)CertStatusManager::getStatusPvFromCert(cert.get());
        });
    }

    // (d) getCertIdFromCert on a cert with no Authority Key Identifier -> CertStatusIdException
    {
        const auto cert = makeBareCert();
        testThrows<CertStatusIdException>([&]() {
            (void)CertStatusManager::getCertIdFromCert(cert.get());
        });
    }

    // (e) getCertIdFromCert with an AKID present -> a non-empty cert id
    //     (issuer id + serial). Confirms the id is derived from the cert itself.
    {
        const auto cert = makeBareCert();
        addAkid(cert.get());
        testTrue(!CertStatusManager::getCertIdFromCert(cert.get()).empty());
    }

    return testDone();
}
