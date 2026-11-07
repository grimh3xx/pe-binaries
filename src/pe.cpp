#include "pe.hpp"

#include <cmath>
#include <cstring>
#include <fstream>

namespace pes {

double entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < len; ++i) freq[data[i]]++;
    double h = 0.0;
    const double n = static_cast<double>(len);
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = freq[i] / n;
        h -= p * std::log2(p);
    }
    return h; // 0 (uniform/constant) .. 8 (maximally random)
}

// Safe bounded read of a trivially-copyable struct from the byte buffer.
template <typename T>
static bool readAt(const std::vector<uint8_t>& buf, size_t off, T& out) {
    if (off + sizeof(T) > buf.size()) return false;
    std::memcpy(&out, buf.data() + off, sizeof(T));
    return true;
}

std::optional<Image> load(const std::string& path, std::string& error) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) { error = "cannot open file"; return std::nullopt; }

    std::streamsize size = f.tellg();
    if (size <= 0) { error = "empty file"; return std::nullopt; }
    f.seekg(0);

    Image img;
    img.fileSize = static_cast<uint64_t>(size);
    img.bytes.resize(static_cast<size_t>(size));
    if (!f.read(reinterpret_cast<char*>(img.bytes.data()), size)) {
        error = "read failed";
        return std::nullopt;
    }

    DosHeader dos;
    if (!readAt(img.bytes, 0, dos) || dos.e_magic != 0x5A4D) {
        error = "not a PE (missing MZ)";
        return std::nullopt;
    }

    size_t ntOff = static_cast<size_t>(dos.e_lfanew);
    uint32_t sig = 0;
    if (!readAt(img.bytes, ntOff, sig) || sig != 0x00004550) { // "PE\0\0"
        error = "not a PE (missing PE signature)";
        return std::nullopt;
    }

    size_t fhOff = ntOff + 4;
    FileHeader fh;
    if (!readAt(img.bytes, fhOff, fh)) { error = "truncated file header"; return std::nullopt; }

    img.machine = fh.Machine;
    img.timeDateStamp = fh.TimeDateStamp;
    img.numberOfSections = fh.NumberOfSections;
    img.isDll = (fh.Characteristics & 0x2000) != 0;

    size_t ohOff = fhOff + sizeof(FileHeader);
    uint16_t magic = 0;
    if (!readAt(img.bytes, ohOff, magic)) { error = "truncated optional header"; return std::nullopt; }
    img.is64 = (magic == 0x20b);

    // Data directories begin right after the fixed optional-header body, whose
    // size differs between PE32 and PE32+. Read SizeOfImage + the security dir.
    OptionalHeader64 oh{};
    if (img.is64) {
        if (!readAt(img.bytes, ohOff, oh)) { error = "truncated PE32+ optional header"; return std::nullopt; }
        img.sizeOfImage = oh.SizeOfImage;
    } else {
        // PE32 layout diverges at ImageBase; read the fields we need by offset.
        uint32_t sizeOfImage = 0;
        if (!readAt(img.bytes, ohOff + 56, sizeOfImage)) { error = "truncated PE32 optional header"; return std::nullopt; }
        img.sizeOfImage = sizeOfImage;
    }

    // NumberOfRvaAndSizes and the directory array sit at a magic-dependent offset.
    size_t dirCountOff = img.is64 ? ohOff + 108 : ohOff + 92;
    uint32_t numDirs = 0;
    if (readAt(img.bytes, dirCountOff, numDirs)) {
        size_t dirArrOff = dirCountOff + 4;
        if (DIR_SECURITY < static_cast<int>(numDirs)) {
            readAt(img.bytes, dirArrOff + DIR_SECURITY * sizeof(DataDirectory), img.security);
        }
    }

    // Section table follows the whole optional header.
    size_t secOff = ohOff + fh.SizeOfOptionalHeader;
    uint64_t maxRawEnd = secOff + static_cast<uint64_t>(fh.NumberOfSections) * sizeof(SectionHeader);

    for (uint16_t i = 0; i < fh.NumberOfSections; ++i) {
        SectionHeader sh;
        if (!readAt(img.bytes, secOff + i * sizeof(SectionHeader), sh)) break;

        Section s;
        char nameBuf[9] = {0};
        std::memcpy(nameBuf, sh.Name, 8);
        s.name = nameBuf;
        s.virtualSize = sh.VirtualSize;
        s.rawSize = sh.SizeOfRawData;
        s.rawOffset = sh.PointerToRawData;
        s.characteristics = sh.Characteristics;

        if (s.rawSize > 0 && s.rawOffset + s.rawSize <= img.bytes.size()) {
            s.entropy = entropy(img.bytes.data() + s.rawOffset, s.rawSize);
        }
        if (s.rawSize > 0) {
            maxRawEnd = std::max<uint64_t>(maxRawEnd, static_cast<uint64_t>(s.rawOffset) + s.rawSize);
        }
        img.sections.push_back(std::move(s));
    }

    // Anything after the last section's raw data (and outside the cert table)
    // is overlay — the classic home of appended bloat.
    uint64_t certEnd = img.security.VirtualAddress
                           ? static_cast<uint64_t>(img.security.VirtualAddress) + img.security.Size
                           : 0;
    uint64_t declaredEnd = std::max(maxRawEnd, certEnd);
    if (img.fileSize > declaredEnd) {
        img.overlayOffset = declaredEnd;
        img.overlaySize = img.fileSize - declaredEnd;
    }

    return img;
}

} // namespace pes
