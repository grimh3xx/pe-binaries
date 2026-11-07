#include "checks.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>

namespace pes {

const char* severityName(Severity s) {
    switch (s) {
        case Severity::High:   return "HIGH";
        case Severity::Medium: return "MEDIUM";
        case Severity::Low:    return "LOW";
        default:               return "INFO";
    }
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
    // An overlay larger than a few MB, or more than half the file, is a
    // classic size-inflation trick to exceed an AV's max scan size.
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

    // A section whose raw data is far larger than its virtual size, with low
    // entropy, is padding that never loads into memory.
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
        out.push_back({Severity::Info, "GO_BUILDID_PRESENT",
            "Go build ID present", "Build ID intact — no tampering indicator here."});
    }
}

// --- Signature: Authenticode certificate table ----------------------------
static void checkSignature(const Image& img, std::vector<Finding>& out) {
    if (img.security.VirtualAddress == 0 || img.security.Size == 0) {
        out.push_back({Severity::Low, "UNSIGNED", "No Authenticode signature",
            "No certificate table. Unsigned on its own is common, but combined "
            "with other flags it weakens provenance."});
        return;
    }
    out.push_back({Severity::Info, "SIGNED", "Authenticode signature present",
        "Certificate table of " + std::to_string(img.security.Size) +
        " bytes at offset " + std::to_string(img.security.VirtualAddress) +
        ". (PE-Sentinel reports presence; it does not validate the chain.)"});
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

// --- Packing: suspiciously high-entropy executable sections ----------------
static void checkPacking(const Image& img, std::vector<Finding>& out) {
    for (const auto& s : img.sections) {
        bool exec = (s.characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
        if (s.rawSize >= 1024 && s.entropy > 7.2) {
            out.push_back({exec ? Severity::Medium : Severity::Low, "HIGH_ENTROPY",
                "High-entropy section '" + s.name + "'",
                "Entropy " + std::to_string(s.entropy).substr(0, 4) + "/8" +
                (exec ? " in an executable section" : "") +
                " suggests packing or encryption."});
        }
    }
}

std::vector<Finding> analyze(const Image& img) {
    std::vector<Finding> out;
    checkBloat(img, out);
    checkBuildId(img, out);
    checkSignature(img, out);
    checkTimestamp(img, out);
    checkPacking(img, out);

    std::stable_sort(out.begin(), out.end(), [](const Finding& a, const Finding& b) {
        return static_cast<int>(a.severity) > static_cast<int>(b.severity);
    });
    return out;
}

} // namespace pes
