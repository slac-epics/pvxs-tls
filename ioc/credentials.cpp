/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 *
 * Author George S. McIntyre <george@level-n.com>, 2023
 *
 */

#include <pvxs/credentials.h>

#include <utilpvt.h>

namespace pvxs {
namespace ioc {

#ifdef EPICS_ASLIB_HAS_SUBJECT_UAG
namespace {
/**
 * @brief Whether a keyed subject string names more than one field
 *
 * A subject carrying only a common name is written as a single pair and so
 * matches nothing the bare common name already matches.  A comma inside single
 * quotes belongs to a value and does not start a second pair.
 */
bool namesMoreThanOneField(const std::string& subject) {
    auto in_quote = false;
    for (const auto c : subject) {
        if (c == '\'')
            in_quote = !in_quote;
        else if (c == ',' && !in_quote)
            return true;
    }
    return false;
}
}  // namespace
#endif

/**
 * eg.
 * "username"  implies "ca/" prefix
 * "krb/principle"
 * "role/groupname"
 * "CN=alice,OU=staff,O=acme"
 *
 * @param clientCredentials The client credentials to be used for the credentials object
 */

Credentials::Credentials(const server::ClientCredentials& clientCredentials) {
    SockAddr addr(clientCredentials.peer);
    addr.setPort(0);
    host = std::string(SB()<<addr.map6to4());
    method = clientCredentials.method;
    authority = clientCredentials.authority;
    issuer_id = clientCredentials.issuer_id;
    serial = clientCredentials.serial;
    isTLS = clientCredentials.isTLS;
    cred.emplace_back(clientCredentials.account);

#ifdef EPICS_ASLIB_HAS_SUBJECT_UAG
    // The peer certificate's subject is offered as a further identity, so that a
    // user access group entry can name the organization or the organizational
    // unit rather than the common name alone.  It is added to the list, never
    // put in place of the bare common name, so every entry already written goes
    // on meaning what it meant.
    if (clientCredentials.method == "x509" && namesMoreThanOneField(clientCredentials.subject)) {
        cred.emplace_back(clientCredentials.subject);
    }
#endif

    for (const auto& role: clientCredentials.roles()) {
        cred.emplace_back(SB() << "role/" << role);
    }
}
} // pvxs
} // ioc
