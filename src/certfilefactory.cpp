/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "certfilefactory.h"

#include <fstream>

#include "p12filefactory.h"

namespace pvxs {
namespace certs {

cert_factory_ptr IdFileFactory::create(const std::string& filename, const std::string& password, X509* cert_ptr,
                                       STACK_OF(X509) * certs_ptr, const std::string& pem_string) {
    const std::string ext = getExtension(filename);
    if (ext == "p12" || ext == "pfx") {
        if (cert_ptr) return make_factory_ptr<P12FileFactory>(filename, password, cert_ptr, certs_ptr);
        return make_factory_ptr<P12FileFactory>(filename, password, pem_string);
    }
    throw std::runtime_error(SB() << ": Unsupported keychain file extension (expected p12 or pfx): \"" << (ext.empty() ? "<none>" : ext) << "\"");
}

}  // namespace certs
}  // namespace pvxs
