/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#ifndef PVXS_P12_FILE_READER_H
#define PVXS_P12_FILE_READER_H

#include <memory>

#include "idfilereader.h"

namespace pvxs {
namespace certs {

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

#endif  // PVXS_P12_FILE_READER_H
