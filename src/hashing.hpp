// PE-Binaries — self-contained MD5 and SHA-256 (no external crypto deps).
// Used for file IOCs (SHA-256, MD5) and the import hash (imphash).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pes {

std::string md5_hex(const uint8_t* data, size_t len);
std::string sha256_hex(const uint8_t* data, size_t len);

inline std::string md5_hex(const std::string& s) {
    return md5_hex(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

} // namespace pes
