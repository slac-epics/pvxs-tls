/*
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "idfilereader.h"

#include <fstream>

#include "p12filereader.h"

namespace pvxs {
namespace certs {

cert_factory_ptr IdFileReader::createReader(const std::string& filename, const std::string& password) {
    const std::string ext = getExtension(filename);
    if (ext == "p12" || ext == "pfx") {
        return make_factory_ptr<P12FileReader>(filename, password);
    }
    throw std::runtime_error(SB() << ": Unsupported keychain file extension (expected p12 or pfx): \"" << (ext.empty() ? "<none>" : ext) << "\"");
}

}  // namespace certs
}  // namespace pvxs
