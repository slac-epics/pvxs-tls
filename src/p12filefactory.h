/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_P12_FILE_FACTORY_H
#define PVXS_P12_FILE_FACTORY_H

#include <memory>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

#include <pvxs/version.h>

#include "certfilefactory.h"
#include "ownedptr.h"
#include "security.h"

namespace pvxs {
namespace certs {

/**
 * @class P12FileFactory
 *
 * @brief Manages certificate file operations.
 */
class P12FileFactory final : public IdFileFactory {
   public:
    P12FileFactory(const std::string &filename, const std::string &password, X509 *cert_ptr, stack_st_X509 *certs_ptr)
        : IdFileFactory(filename, password, cert_ptr, certs_ptr, "") {}

    P12FileFactory(const std::string &filename, const std::string &password, const std::string &pem_string)
        : IdFileFactory(filename, password, nullptr, nullptr, pem_string) {}

    CertData getCertDataFromFile() override;
};

}  // namespace certs
}  // namespace pvxs

#endif  // PVXS_P12_FILE_FACTORY_H
