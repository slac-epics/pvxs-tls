/**
 * Copyright - See the COPYRIGHT that is included with this distribution.
 * pvxs is distributed subject to a Software License Agreement found
 * in file LICENSE that is included with this distribution.
 */

#include "statuscache.h"

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <direct.h>
#  include <io.h>
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include <pvxs/log.h>

#include "utilpvt.h"

// Portability note: atomicRename() wraps the platform-specific "replace dst
// atomically" operation.
//   POSIX: rename(2) atomically replaces the destination per POSIX.1-2017.
//   Windows: rename() / MoveFile() refuse to replace an existing file; use
//            MoveFileExW with MOVEFILE_REPLACE_EXISTING instead.
namespace {
bool atomicRename(const std::string &src, const std::string &dst) {
#ifdef _WIN32
    auto toWide = [](const std::string &s) -> std::wstring {
        if (s.empty()) return {};
        int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
        std::wstring w(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
        return w;
    };

    return MoveFileExW(toWide(src).c_str(), toWide(dst).c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    return std::rename(src.c_str(), dst.c_str()) == 0;
#endif
}
} // namespace

DEFINE_LOGGER(cachelog, "pvxs.certs.cache");

namespace pvxs {
namespace certs {

namespace {

std::string cacheFilePath(const std::string &cert_id, const std::string &cache_dir) {
    return cache_dir + "/" + cert_id + ".ocsp";
}

std::string cacheTempPath(const std::string &cert_id, const std::string &cache_dir) {
    return cache_dir + "/" + cert_id + ".ocsp.tmp";
}

bool ensureCacheDirExists(const std::string &cache_dir) {
    // ensureDirectoryExists expects a filepath (directory + trailing sep + dummy)
    std::string probe = cache_dir + "/x";
    try {
        ensureDirectoryExists(probe, false);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

std::string getStatusCacheDir() {
    const char *env = std::getenv("EPICS_PVA_STATUS_CACHE_DIR");
    if (env && env[0] != '\0')
        return env;
    return getXdgPvaDataHome() + "/status_cache";
}

std::string resolveStatusCacheDir(const std::string &override_dir) {
    return override_dir.empty() ? getStatusCacheDir() : override_dir;
}

bool isStatusCacheEnabled() {
    const char *env = std::getenv("EPICS_PVA_NO_STATUS_CACHE");
    if (!env)
        return true;
    try {
        return !parseTo<bool>(std::string(env));
    } catch (...) {
        return true;
    }
}

bool writeCacheFile(const std::string &cert_id, const uint8_t *data, size_t len) {
    return writeCacheFile(cert_id, data, len, std::string{});
}

bool writeCacheFile(const std::string &cert_id, const uint8_t *data, size_t len,
                    const std::string &cache_dir_override) {
    if (cert_id.empty() || !data || len == 0)
        return false;

    const auto cache_dir = resolveStatusCacheDir(cache_dir_override);

    if (!ensureCacheDirExists(cache_dir)) {
        log_debug_printf(cachelog, "Cannot create cache directory: %s\n",
                         cache_dir.c_str());
        return false;
    }

    const auto tmp = cacheTempPath(cert_id, cache_dir);
    const auto dst = cacheFilePath(cert_id, cache_dir);

    std::unique_ptr<FILE> fp(std::fopen(tmp.c_str(), "wb"));
    if (!fp) {
        log_debug_printf(cachelog, "Cannot open temp cache file %s: %s\n",
                         tmp.c_str(), std::strerror(errno));
        return false;
    }

    {
        FLock lock(fp.get(), true);
        if (std::fwrite(data, 1, len, fp.get()) != len) {
            log_debug_printf(cachelog, "Short write to %s\n", tmp.c_str());
            fp.reset();
            std::remove(tmp.c_str());
            return false;
        }
    }

    fp.reset();

    if (!atomicRename(tmp, dst)) {
        log_debug_printf(cachelog, "Cannot rename %s -> %s\n",
                         tmp.c_str(), dst.c_str());
        std::remove(tmp.c_str());
        return false;
    }

    log_debug_printf(cachelog, "Cached OCSP status for %s\n", cert_id.c_str());
    return true;
}

std::vector<uint8_t> readCacheFile(const std::string &cert_id) {
    return readCacheFile(cert_id, std::string{});
}

std::vector<uint8_t> readCacheFile(const std::string &cert_id,
                                   const std::string &cache_dir_override) {
    if (cert_id.empty())
        return {};

    const auto path = cacheFilePath(cert_id, resolveStatusCacheDir(cache_dir_override));

    std::unique_ptr<FILE> fp(std::fopen(path.c_str(), "rb"));
    if (!fp)
        return {};

    FLock lock(fp.get(), false);

    if (std::fseek(fp.get(), 0, SEEK_END) != 0)
        return {};
    const long sz = std::ftell(fp.get());
    if (sz <= 0)
        return {};
    std::rewind(fp.get());

    std::vector<uint8_t> buf(static_cast<size_t>(sz));
    if (std::fread(buf.data(), 1, buf.size(), fp.get()) != buf.size())
        return {};

    return buf;
}

void deleteCacheFile(const std::string &cert_id) {
    deleteCacheFile(cert_id, std::string{});
}

void deleteCacheFile(const std::string &cert_id,
                     const std::string &cache_dir_override) {
    if (cert_id.empty())
        return;
    const auto path = cacheFilePath(cert_id, resolveStatusCacheDir(cache_dir_override));
    std::remove(path.c_str());
}

} // namespace certs
} // namespace pvxs
