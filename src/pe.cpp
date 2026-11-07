#include "pe.hpp"
#include "hashing.hpp"

#include <algorithm>
#include <cctype>
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

// Safe bounded read of a trivially-copyable value from the byte buffer.
template <typename T>
static bool readAt(const std::vector<uint8_t>& buf, size_t off, T& out) {
    if (off + sizeof(T) > buf.size()) return false;
    std::memcpy(&out, buf.data() + off, sizeof(T));
    return true;
}

uint64_t Image::rvaToOffset(uint32_t rva) const {
    if (rva < sizeOfHeaders) return rva; // inside the header region
    for (const auto& s : sections) {
        uint32_t span = std::max(s.virtualSize, s.rawSize);
        if (rva >= s.virtualAddr && rva < s.virtualAddr + span) {
            uint64_t delta = rva - s.virtualAddr;
            if (delta < s.rawSize) return s.rawOffset + delta;
            return 0; // falls in uninitialised (bss) space
        }
    }
    return 0;
}

// Read a NUL-terminated ASCII string at a file offset, capped for safety.
static std::string readCStr(const std::vector<uint8_t>& buf, uint64_t off, size_t cap = 256) {
    std::string s;
    for (size_t i = 0; i < cap && off + i < buf.size(); ++i) {
        char c = static_cast<char>(buf[off + i]);
        if (c == '\0') break;
        s.push_back(c);
    }
    return s;
}

static std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ------------------------------------------------------------ import table
static void parseImports(Image& img) {
    if (img.dirs.size() <= 1) return;
    DataDirectory imp = img.dirs[1]; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if (!imp.VirtualAddress || !imp.Size) return;

    uint64_t base = img.rvaToOffset(imp.VirtualAddress);
    if (!base) return;
    const int thunkSz = img.is64 ? 8 : 4;
    const uint64_t ordFlag = img.is64 ? 0x8000000000000000ull : 0x80000000ull;

    for (int d = 0; d < 4096; ++d) {
        uint64_t desc = base + static_cast<uint64_t>(d) * 20;
        uint32_t oft = 0, nameRva = 0, ft = 0;
        if (!readAt(img.bytes, desc, oft)) break;
        readAt(img.bytes, desc + 12, nameRva);
        readAt(img.bytes, desc + 16, ft);
        if (oft == 0 && nameRva == 0 && ft == 0) break; // null terminator

        Import entry;
        uint64_t nameOff = img.rvaToOffset(nameRva);
        entry.dll = nameOff ? readCStr(img.bytes, nameOff) : "";

        uint32_t thunkRva = oft ? oft : ft;
        uint64_t thunk = img.rvaToOffset(thunkRva);
        for (int i = 0; thunk && i < 8192; ++i) {
            uint64_t val = 0;
            if (img.is64) { if (!readAt(img.bytes, thunk + i * thunkSz, val)) break; }
            else { uint32_t v32 = 0; if (!readAt(img.bytes, thunk + i * thunkSz, v32)) break; val = v32; }
            if (val == 0) break;
            if (val & ordFlag) {
                entry.funcs.push_back("ord" + std::to_string(val & 0xffff));
            } else {
                uint64_t byName = img.rvaToOffset(static_cast<uint32_t>(val));
                if (byName) entry.funcs.push_back(readCStr(img.bytes, byName + 2)); // skip hint
            }
        }
        if (!entry.dll.empty()) img.imports.push_back(std::move(entry));
    }
}

// pefile-compatible import hash: md5 of "lib.func,lib.func,..." lowercased.
static void computeImphash(Image& img) {
    std::string joined;
    for (const auto& imp : img.imports) {
        std::string lib = lower(imp.dll);
        auto dot = lib.find('.');
        if (dot != std::string::npos) lib = lib.substr(0, dot);
        for (const auto& fn : imp.funcs) {
            if (!joined.empty()) joined.push_back(',');
            joined += lib + "." + lower(fn);
        }
    }
    if (!joined.empty()) img.imphash = md5_hex(joined);
}

// ------------------------------------------------------------ TLS callbacks
static void parseTls(Image& img) {
    if (img.dirs.size() <= 9) return;
    DataDirectory tls = img.dirs[9]; // IMAGE_DIRECTORY_ENTRY_TLS
    if (!tls.VirtualAddress || !tls.Size) return;
    uint64_t off = img.rvaToOffset(tls.VirtualAddress);
    if (!off) return;
    uint64_t cbVa = 0;
    if (img.is64) readAt(img.bytes, off + 24, cbVa);
    else { uint32_t v = 0; readAt(img.bytes, off + 12, v); cbVa = v; }
    if (cbVa == 0 || cbVa < img.imageBase) return;
    uint64_t cbOff = img.rvaToOffset(static_cast<uint32_t>(cbVa - img.imageBase));
    if (!cbOff) { img.hasTlsCallbacks = true; return; } // table present, unresolved
    uint64_t first = 0;
    if (img.is64) readAt(img.bytes, cbOff, first);
    else { uint32_t v = 0; readAt(img.bytes, cbOff, v); first = v; }
    img.hasTlsCallbacks = (first != 0);
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

    // Fields at offsets shared by PE32 and PE32+.
    readAt(img.bytes, ohOff + 16, img.entryPoint);
    readAt(img.bytes, ohOff + 56, img.sizeOfImage);
    readAt(img.bytes, ohOff + 60, img.sizeOfHeaders);
    readAt(img.bytes, ohOff + 64, img.checksumStored);
    if (img.is64) {
        readAt(img.bytes, ohOff + 24, img.imageBase);
    } else {
        uint32_t ib = 0; readAt(img.bytes, ohOff + 28, ib); img.imageBase = ib;
    }

    // Data directories.
    size_t dirCountOff = img.is64 ? ohOff + 108 : ohOff + 92;
    uint32_t numDirs = 0;
    if (readAt(img.bytes, dirCountOff, numDirs)) {
        size_t dirArrOff = dirCountOff + 4;
        numDirs = std::min<uint32_t>(numDirs, 16);
        for (uint32_t i = 0; i < numDirs; ++i) {
            DataDirectory dd{0, 0};
            readAt(img.bytes, dirArrOff + i * sizeof(DataDirectory), dd);
            img.dirs.push_back(dd);
        }
        if (DIR_SECURITY < static_cast<int>(img.dirs.size())) img.security = img.dirs[DIR_SECURITY];
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
        s.virtualAddr = sh.VirtualAddress;
        s.virtualSize = sh.VirtualSize;
        s.rawSize = sh.SizeOfRawData;
        s.rawOffset = sh.PointerToRawData;
        s.characteristics = sh.Characteristics;

        if (s.rawSize > 0 && s.rawOffset + s.rawSize <= img.bytes.size())
            s.entropy = entropy(img.bytes.data() + s.rawOffset, s.rawSize);
        if (s.rawSize > 0)
            maxRawEnd = std::max<uint64_t>(maxRawEnd, static_cast<uint64_t>(s.rawOffset) + s.rawSize);
        img.sections.push_back(std::move(s));
    }

    // Overlay: anything past the last section's raw data and the cert table.
    uint64_t certEnd = img.security.VirtualAddress
                           ? static_cast<uint64_t>(img.security.VirtualAddress) + img.security.Size
                           : 0;
    uint64_t declaredEnd = std::max(maxRawEnd, certEnd);
    if (img.fileSize > declaredEnd) {
        img.overlayOffset = declaredEnd;
        img.overlaySize = img.fileSize - declaredEnd;
    }

    parseImports(img);
    computeImphash(img);
    parseTls(img);

    img.sha256 = sha256_hex(img.bytes.data(), img.bytes.size());
    img.md5 = md5_hex(img.bytes.data(), img.bytes.size());

    return img;
}

} // namespace pes
