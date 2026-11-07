// PE-Binaries — portable PE structures and reader
// Defensive binary-analysis tool. Read-only: never modifies the target.
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace pes {

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;      // "MZ"
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;     // offset to NT headers
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// Shared prefix of the 32/64-bit optional headers up to the data directories.
struct OptionalHeader64 {
    uint16_t Magic;              // 0x10b = PE32, 0x20b = PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};
#pragma pack(pop)

// Directory index for the Authenticode security directory.
constexpr int DIR_SECURITY = 4;

struct Section {
    std::string name;
    uint32_t    virtualAddr = 0;
    uint32_t    virtualSize = 0;
    uint32_t    rawSize = 0;
    uint32_t    rawOffset = 0;
    uint32_t    characteristics = 0;
    double      entropy = 0.0;   // 0..8 bits/byte over the raw bytes

    bool exec()  const { return characteristics & 0x20000000u; } // MEM_EXECUTE
    bool write() const { return characteristics & 0x80000000u; } // MEM_WRITE
};

// One imported DLL and the symbols pulled from it.
struct Import {
    std::string dll;
    std::vector<std::string> funcs;   // "ord123" for ordinal-only imports
};

// A parsed PE image. Holds just enough to reason about evasion artifacts.
struct Image {
    bool        is64 = false;
    bool        isDll = false;
    uint16_t    machine = 0;
    uint32_t    timeDateStamp = 0;
    uint16_t    numberOfSections = 0;
    uint32_t    sizeOfImage = 0;
    uint32_t    sizeOfHeaders = 0;
    uint32_t    entryPoint = 0;      // AddressOfEntryPoint (RVA)
    uint64_t    imageBase = 0;
    uint32_t    checksumStored = 0;  // OptionalHeader.CheckSum
    uint64_t    fileSize = 0;

    std::vector<Section> sections;
    std::vector<DataDirectory> dirs; // all data directories, by index

    std::vector<Import> imports;     // parsed import table
    bool        hasTlsCallbacks = false;

    // Authenticode security directory (certificate table), if present.
    DataDirectory security{0, 0};

    // Trailing bytes after the last section's raw data — the "overlay".
    uint64_t overlayOffset = 0;
    uint64_t overlaySize = 0;

    // IOCs (filled by load()).
    std::string sha256;
    std::string md5;
    std::string imphash;             // pefile-compatible import hash

    // Raw file bytes, kept for entropy / string scans.
    std::vector<uint8_t> bytes;

    // Map a relative virtual address to a file offset (0 if unmapped).
    uint64_t rvaToOffset(uint32_t rva) const;
};

// Parse a PE file from disk. Returns nullopt with `error` set on failure.
std::optional<Image> load(const std::string& path, std::string& error);

// Shannon entropy (bits/byte) over a byte range.
double entropy(const uint8_t* data, size_t len);

} // namespace pes
