/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#ifndef PVXS_CREDENTIALS_H
#define PVXS_CREDENTIALS_H

#include <vector>
#include <string>

#include <pvxs/source.h>

namespace pvxs {
namespace ioc {

/**
 * @brief Credentials class
 *
 * @details This class is used to store the credentials for a client or server.
 *
 * @param clientCredentials The client credentials to be used for the credentials object
 *
 */
class Credentials {
public:
    std::vector<std::string> cred;
    std::string method;
    std::string authority;
    std::string host;
    std::string issuer_id;
    std::string serial;
    explicit Credentials(const server::ClientCredentials& clientCredentials);
    Credentials(const Credentials&) = delete;
    Credentials(Credentials&&) = default;
};

} // pvxs
} // ioc

#endif //PVXS_CREDENTIALS_H
