#include "checks.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <set>
#include <string>

namespace pes {

const char* severityName(Severity s) {
    switch (s) {
        case Severity::High:   return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low:    return "LOW";
        default:               return "INFO";
    }
}

static std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Does the raw image contain this ASCII needle anywhere?
static bool contains(const Image& img, const char* needle) {
    size_t n = std::strlen(needle);
    if (n == 0 || img.bytes.size() < n) return false;
    auto it = std::search(img.bytes.begin(), img.bytes.end(), needle, needle + n);
    return it != img.bytes.end();
}

static bool looksGo(const Image& img) {
    for (const auto& s : img.sections)
        if (s.name == ".gopclntab" || s.name == ".go.buildinfo") return true;
    return contains(img, "Go build ID:") || contains(img, "go:buildid") ||
           contains(img, "runtime.main") || contains(img, "golang.org/");
}

// --- Bloat: oversized overlay or a huge low-entropy section ----------------
static void checkBloat(const Image& img, std::vector<Finding>& out) {
    if (img.overlaySize > 0) {
        double frac = static_cast<double>(img.overlaySize) / img.fileSize;
        double entr = entropy(img.bytes.data() + img.overlayOffset,
                              static_cast<size_t>(img.overlaySize));
        bool big = img.overlaySize > (5ull << 20) || frac > 0.5;
        if (big) {
            Severity sev = (entr < 1.0 || frac > 0.8) ? Severity::High : Severity::Medium;
            out.push_back({sev, "BLOAT_OVERLAY", "Oversized file overlay",
                "Overlay of " + std::to_string(img.overlaySize) + " bytes (" +
                std::to_string(static_cast<int>(frac * 100)) + "% of file) at offset " +
                std::to_string(img.overlayOffset) + ", entropy " +
                std::to_string(entr).substr(0, 4) +
                ". Low-entropy padding this large is a hallmark of size inflation."});
        }
    }
    for (const auto& s : img.sections) {
        if (s.rawSize >= (4u << 20) && s.rawSize > s.virtualSize * 4 && s.entropy < 1.5) {
            out.push_back({Severity::Medium, "BLOAT_SECTION",
                "Padded section '" + s.name + "'",
                "Raw size " + std::to_string(s.rawSize) + " vs virtual " +
                std::to_string(s.virtualSize) + ", entropy " +
                std::to_string(s.entropy).substr(0, 4) +
                ". Raw bytes with no in-memory counterpart look like filler."});
        }
    }
}

// --- Build ID: Go binary with its build ID stripped -----------------------
static void checkBuildId(const Image& img, std::vector<Finding>& out) {
    if (!looksGo(img)) return;
    bool hasBuildId = contains(img, "Go build ID:") || contains(img, "go:buildid");
    bool hasBuildInfo = false;
    for (const auto& s : img.sections)
        if (s.name == ".go.buildinfo") hasBuildInfo = true;
    if (!hasBuildId) {
        out.push_back({Severity::Medium, "GO_BUILDID_STRIPPED",
            "Go binary with no build ID",
            std::string("Image shows Go runtime markers but the build ID is absent") +
            (hasBuildInfo ? " despite a .go.buildinfo section" : "") +
            ". Stripping the build ID is a known signature-evasion step."});
    } else {
        out.push_back({Severity::Info, "GO_BUILDID_PRESENT", "Go build ID present",
            "Build ID intact — no tampering indicator here."});
    }
}

// --- Signature + checksum -------------------------------------------------
// PE header checksum, with the 4-byte CheckSum field treated as zero.
static uint32_t computeChecksum(const Image& img) {
    // The CheckSum field lives in the optional header; find its file offset.
    uint32_t lfanew = 0;
    std::memcpy(&lfanew, img.bytes.data() + 0x3C, 4);
    size_t csOff = lfanew + 4 + 20 + 64; // PE sig + file header + opt header off 64
    uint64_t sum = 0;
    const auto& b = img.bytes;
    size_t n = b.size();
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint32_t w = b[i] | (uint32_t(b[i + 1]) << 8);
        if (i == csOff || i == csOff + 2) w = 0; // zero out stored checksum
        sum += w;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if (n & 1) { sum += b[n - 1]; sum = (sum & 0xffff) + (sum >> 16); }
    sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint32_t>(sum) + static_cast<uint32_t>(n);
}

static void checkSignature(const Image& img, std::vector<Finding>& out) {
    bool signed_ = img.security.VirtualAddress != 0 && img.security.Size != 0;
    if (!signed_) {
        out.push_back({Severity::Low, "UNSIGNED", "No Authenticode signature",
            "No certificate table. Unsigned on its own is common, but combined "
            "with other flags it weakens provenance."});
    } else {
        out.push_back({Severity::Info, "SIGNED", "Authenticode signature present",
            "Certificate table of " + std::to_string(img.security.Size) +
            " bytes. (Presence only — the chain is not validated.)"});
    }
    if (img.checksumStored != 0) {
        uint32_t calc = computeChecksum(img);
        if (calc != img.checksumStored) {
            out.push_back({signed_ ? Severity::Medium : Severity::Low, "CHECKSUM_INVALID",
                "Header checksum mismatch",
                "Stored " + std::to_string(img.checksumStored) + " vs computed " +
                std::to_string(calc) +
                (signed_ ? ". A signed file with a bad checksum was modified after signing."
                         : ". The optional-header checksum does not match the file.")});
        }
    }
}

// --- Timestamp anomalies ---------------------------------------------------
static void checkTimestamp(const Image& img, std::vector<Finding>& out) {
    uint32_t ts = img.timeDateStamp;
    if (ts == 0) {
        out.push_back({Severity::Low, "TS_ZERO", "Zeroed compile timestamp",
            "TimeDateStamp is 0 — often a reproducible build, but also used to "
            "erase build provenance."});
        return;
    }
    time_t now = time(nullptr);
    if (static_cast<time_t>(ts) > now + 86400) {
        out.push_back({Severity::Medium, "TS_FUTURE", "Future compile timestamp",
            "TimeDateStamp " + std::to_string(ts) + " is in the future — a forged "
            "or tampered header value."});
    }
}

// --- Sections: entropy, RWX, odd names, entry point ------------------------
static const std::set<std::string> kStdSections = {
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".pdata", ".xdata",
    ".reloc", ".rsrc", ".tls", ".debug", ".gfids", ".crt", ".00cfg", ".didat",
    ".gehcont", ".textbss", ".sdata", ".voltbl",
};
static const std::set<std::string> kPackerSections = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".nsp0", ".nsp1", ".petite",
    ".themida", "mpress1", "mpress2", ".vmp0", ".vmp1", ".enigma1",
};

static void checkSections(const Image& img, std::vector<Finding>& out) {
    for (const auto& s : img.sections) {
        if (s.rawSize >= 1024 && s.entropy > 7.2) {
            out.push_back({s.exec() ? Severity::Medium : Severity::Low, "HIGH_ENTROPY",
                "High-entropy section '" + s.name + "'",
                "Entropy " + std::to_string(s.entropy).substr(0, 4) + "/8" +
                (s.exec() ? " in an executable section" : "") +
                " suggests packing or encryption."});
        }
        if (s.exec() && s.write()) {
            out.push_back({Severity::High, "RWX_SECTION",
                "Writable + executable section '" + s.name + "'",
                "Section is both writable and executable (RWX) — a strong indicator "
                "of self-modifying code, unpacking stubs or injected shellcode."});
        }
        std::string ln = lower(s.name);
        if (kPackerSections.count(ln)) {
            out.push_back({Severity::Medium, "PACKER_SECTION",
                "Known packer section '" + s.name + "'",
                "Section name matches a known packer/protector layout."});
        } else if (!s.name.empty() && s.name[0] != '/' && !kStdSections.count(ln)) {
            out.push_back({Severity::Low, "ABNORMAL_SECTION",
                "Unusual section name '" + s.name + "'",
                "Not a standard toolchain section name — worth a look, as custom "
                "names often come from packers or manual tampering."});
        }
    }

    // Entry point placement.
    if (img.entryPoint != 0) {
        const Section* host = nullptr;
        for (const auto& s : img.sections) {
            uint32_t span = std::max(s.virtualSize, s.rawSize);
            if (img.entryPoint >= s.virtualAddr && img.entryPoint < s.virtualAddr + span) {
                host = &s; break;
            }
        }
        if (!host) {
            out.push_back({Severity::High, "EP_OUTSIDE",
                "Entry point outside all sections",
                "AddressOfEntryPoint 0x" + std::to_string(img.entryPoint) +
                " maps to no section — typical of manual tampering or a broken loader."});
        } else if (!host->exec()) {
            out.push_back({Severity::High, "EP_NONEXEC",
                "Entry point in a non-executable section",
                "Execution starts in '" + host->name + "', which is not marked "
                "executable — a packer/loader trick."});
        } else if (host->write()) {
            out.push_back({Severity::Medium, "EP_WRITABLE",
                "Entry point in a writable section",
                "Execution starts in writable '" + host->name +
                "' — common for unpackers that rewrite their own code."});
        }
    }
}

// --- Imports: suspicious APIs, dynamic resolution, thin import table -------
static void checkImports(const Image& img, std::vector<Finding>& out) {
    std::set<std::string> apis;
    size_t total = 0;
    for (const auto& imp : img.imports)
        for (const auto& fn : imp.funcs) { apis.insert(lower(fn)); ++total; }

    auto has = [&](const char* a) { return apis.count(lower(a)) != 0; };
    auto collect = [&](std::initializer_list<const char*> list) {
        std::vector<std::string> f;
        for (const char* a : list) if (has(a)) f.push_back(a);
        return f;
    };

    std::vector<std::string> hits;
    Severity worst = Severity::Info;
    auto add = [&](const char* label, const std::vector<std::string>& found, Severity sev) {
        if (found.empty()) return;
        std::string line = std::string(label) + ": ";
        for (size_t i = 0; i < found.size(); ++i) line += (i ? ", " : "") + found[i];
        hits.push_back(line);
        if (static_cast<int>(sev) > static_cast<int>(worst)) worst = sev;
    };

    // Injection: the real signal is a *combination*. A lone helper API is weak.
    auto core = collect({"virtualallocex","writeprocessmemory","createremotethread",
                         "ntcreatethreadex","queueuserapc","rtlcreateuserthread",
                         "ntwritevirtualmemory"});
    auto helper = collect({"setthreadcontext","ntmapviewofsection","ntunmapviewofsection",
                           "resumethread"});
    std::vector<std::string> inj = core;
    inj.insert(inj.end(), helper.begin(), helper.end());
    if (core.size() >= 2)      add("process injection", inj, Severity::High);
    else if (core.size() == 1) add("process injection", inj, Severity::Medium);
    else if (!helper.empty())  add("process-manipulation helpers", helper, Severity::Low);

    add("anti-debug", collect({"isdebuggerpresent","checkremotedebuggerpresent",
        "ntqueryinformationprocess","ntsetinformationthread"}), Severity::Medium);
    add("credential/token", collect({"adjusttokenprivileges","openprocesstoken",
        "lookupprivilegevaluea","lsaretrieveprivatedata"}), Severity::Medium);
    add("input capture / hooking", collect({"setwindowshookexa","setwindowshookexw"}),
        Severity::Medium);

    if (!hits.empty()) {
        std::string detail;
        for (size_t i = 0; i < hits.size(); ++i) detail += (i ? "; " : "") + hits[i];
        out.push_back({worst, "SUSPICIOUS_IMPORTS", "Notable imported APIs", detail + "."});
    }

    if (has("getprocaddress") && (has("loadlibrarya") || has("loadlibraryw")) && total < 15) {
        out.push_back({Severity::Medium, "DYNAMIC_RESOLUTION",
            "Dynamic API resolution with a thin import table",
            "Imports GetProcAddress + LoadLibrary with only " + std::to_string(total) +
            " named imports — APIs are likely resolved at runtime to hide behaviour."});
    }

    bool codeHeavy = false;
    for (const auto& s : img.sections)
        if (s.exec() && s.rawSize > 4096) codeHeavy = true;
    if (codeHeavy && total <= 5) {
        bool highEntropy = false;
        for (const auto& s : img.sections) if (s.entropy > 7.0) highEntropy = true;
        out.push_back({highEntropy ? Severity::Medium : Severity::Low, "FEW_IMPORTS",
            "Very small import table",
            "Only " + std::to_string(total) + " imported functions for a binary with "
            "real code" + (highEntropy ? " and high-entropy sections — classic packed layout."
                                       : " — the real import table may be hidden.")});
    }
}

// --- TLS callbacks ---------------------------------------------------------
static void checkTls(const Image& img, std::vector<Finding>& out) {
    if (img.hasTlsCallbacks) {
        out.push_back({Severity::Low, "TLS_CALLBACK", "TLS callback present",
            "A TLS callback runs before the entry point — used for early "
            "initialisation, but also for anti-debugging and stealth execution."});
    }
}

std::vector<Finding> analyze(const Image& img) {
    std::vector<Finding> out;
    checkBloat(img, out);
    checkBuildId(img, out);
    checkSignature(img, out);
    checkTimestamp(img, out);
    checkSections(img, out);
    checkImports(img, out);
    checkTls(img, out);

    std::stable_sort(out.begin(), out.end(), [](const Finding& a, const Finding& b) {
        return static_cast<int>(a.severity) > static_cast<int>(b.severity);
    });
    return out;
}

int riskScore(const std::vector<Finding>& findings) {
    int score = 0;
    for (const auto& f : findings) {
        switch (f.severity) {
            case Severity::High:   score += 40; break;
            case Severity::Medium: score += 18; break;
            case Severity::Low:    score += 6;  break;
            default: break;
        }
    }
    return std::min(100, score);
}

const char* riskLabel(int score) {
    if (score >= 60) return "HIGH RISK";
    if (score >= 25) return "SUSPICIOUS";
    if (score > 0)   return "LOW RISK";
    return "CLEAN";
}

} // namespace pes
