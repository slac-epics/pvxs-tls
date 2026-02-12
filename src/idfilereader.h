/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_ID_FILE_READER_H
#define PVXS_ID_FILE_READER_H

#include <memory>
#include <string>
#include <utility>

#include <openssl/x509.h>

#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

// Forward declarations
class P12FileReader;
class IdFileReader;

// C++11 implementation of make_unique
template <typename T, typename... Args>
std::unique_ptr<T> make_factory_ptr(Args&&... args) {
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// CertData structure definition
struct CertData {
    ossl_ptr<X509> cert;
    ossl_shared_ptr<STACK_OF(X509)> cert_auth_chain;
    std::shared_ptr<KeyPair> key_pair;
    time_t renew_by{0};

    CertData(ossl_ptr<X509>& newCert, ossl_shared_ptr<STACK_OF(X509)>& newCa) : cert(std::move(newCert)), cert_auth_chain(newCa) {}
    CertData(ossl_ptr<X509>& newCert, ossl_shared_ptr<STACK_OF(X509)>& newCa, std::shared_ptr<KeyPair> key_pair)
        : cert(std::move(newCert)), cert_auth_chain(newCa), key_pair(key_pair) {}
    CertData() = default;
};

typedef std::unique_ptr<IdFileReader> cert_factory_ptr;

class PVXS_API IdFileReader {
   public:
    /**
     * @brief Creates a new IdFile Reader object.
     *
     * This method creates a new CertFileFactory object.
     */
    static cert_factory_ptr createReader(const std::string& filename, const std::string& password = "");

    virtual ~IdFileReader() = default;

    /**
     * @brief Gets the certificate data from the file.
     *
     * This method gets the certificate data including the key from the file.
     * The format (PKCS#12, or Base64-encoded ASCII) is determined by the filename extension.
     */
    virtual CertData getCertDataFromFile() = 0;

   protected:
    IdFileReader(const std::string& filename, const std::string& password = "")
        : filename_(filename), password_(password) {}

    std::string filename_{};
    std::string password_{};

    static std::string getExtension(const std::string& filename) {
        auto pos = filename.find_last_of('.');
        if (pos == std::string::npos) {
            return "";
        }
        return filename.substr(pos + 1);
    }
};

/**
 * @class P12FileReader
 *
 * @brief Manages certificate file operations.
 */
class P12FileReader final : public IdFileReader {
    public:
        P12FileReader(const std::string &filename, const std::string &password)
            : IdFileReader(filename, password) {}

        CertData getCertDataFromFile() override;
};



}  // namespace certs
}  // namespace pvxs

#endif // PVXS_ID_FILE_READER_H
