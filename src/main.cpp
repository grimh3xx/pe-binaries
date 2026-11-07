// PE-Binaries — detects binary-evasion artifacts in PE files.
// Read-only: it inspects and reports; it never alters the target.
#include "checks.hpp"
#include "pe.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <io.h>
#  define ISATTY _isatty
#  define FILENO _fileno
#else
#  include <unistd.h>
#  define ISATTY isatty
#  define FILENO fileno
#endif

namespace {

// ANSI palette — populated only when output is a color-capable terminal.
struct Palette {
    const char* reset = "";
    const char* dim = "";
    const char* bold = "";
    const char* cyan = "";
    const char* red = "";
    const char* yellow = "";
    const char* blue = "";
    const char* green = "";
};
Palette C;

void enableColor() {
    static Palette lit{
        "\033[0m", "\033[2m", "\033[1m", "\033[36m",
        "\033[31m", "\033[33m", "\033[34m", "\033[32m"};
    C = lit;
}

const char* severityColor(pes::Severity s) {
    switch (s) {
        case pes::Severity::High:   return C.red;
        case pes::Severity::Medium: return C.yellow;
        case pes::Severity::Low:    return C.blue;
        default:                    return C.dim;
    }
}

void printBanner() {
    static const char* art = R"ART( ___  ___       ___  _                   _
| _ \| __| ___ | _ )(_) _ _   __ _  _ _ (_) ___  ___
|  _/| _| |___|| _ \| || ' \ / _` || '_|| |/ -_)(_-<
|_|  |___|     |___/|_||_||_|\__,_||_|  |_|\___|/__/
)ART";
    std::printf("%s%s%s%s", C.bold, C.cyan, art, C.reset);
    std::printf("%s evasion-artifact detector for PE binaries%s\n\n", C.dim, C.reset);
}

void printUsage(const char* argv0) {
    std::printf(
        "PE-Binaries — evasion-artifact detector for PE binaries\n"
        "\n"
        "usage: %s [options] <file.exe|file.dll> [more files...]\n"
        "\n"
        "options:\n"
        "  -q, --quiet     only print findings, skip the image summary\n"
        "  -s, --strict    exit non-zero if any MEDIUM or HIGH finding is present\n"
        "      --color     force ANSI color (default: auto when stdout is a TTY)\n"
        "      --no-color  disable ANSI color\n"
        "  -h, --help      show this help\n",
        argv0);
}

const char* machineName(uint16_t m) {
    switch (m) {
        case 0x014c: return "x86";
        case 0x8664: return "x64";
        case 0xaa64: return "ARM64";
        case 0x01c4: return "ARMv7";
        default:     return "unknown";
    }
}

void printSummary(const pes::Image& img) {
    std::printf("  type        : PE32%s %s %s\n", img.is64 ? "+" : "",
                machineName(img.machine), img.isDll ? "DLL" : "EXE");
    std::printf("  file size   : %llu bytes\n", (unsigned long long)img.fileSize);
    std::printf("  sections    : %u\n", img.numberOfSections);
    for (const auto& s : img.sections) {
        std::printf("    %-9s raw=%-10u virt=%-10u entropy=%.2f\n",
                    s.name.c_str(), s.rawSize, s.virtualSize, s.entropy);
    }
    if (img.overlaySize) {
        std::printf("  overlay     : %llu bytes @ offset %llu\n",
                    (unsigned long long)img.overlaySize,
                    (unsigned long long)img.overlayOffset);
    }
}

int analyzeFile(const std::string& path, bool quiet, bool strict) {
    std::string err;
    auto img = pes::load(path, err);
    if (!img) {
        std::fprintf(stderr, "[!] %s: %s\n", path.c_str(), err.c_str());
        return 2;
    }

    std::printf("\n%s=== %s ===%s\n", C.bold, path.c_str(), C.reset);
    if (!quiet) printSummary(*img);

    auto findings = pes::analyze(*img);
    std::printf("  findings    : %s%zu%s\n",
                findings.empty() ? C.green : C.bold, findings.size(), C.reset);

    bool strictHit = false;
    for (const auto& f : findings) {
        const char* col = severityColor(f.severity);
        std::printf("  %s[%-6s]%s %s%-20s%s %s\n", col, pes::severityName(f.severity),
                    C.reset, C.bold, f.id.c_str(), C.reset, f.title.c_str());
        std::printf("            %s%s%s\n", C.dim, f.detail.c_str(), C.reset);
        if (f.severity == pes::Severity::Medium || f.severity == pes::Severity::High)
            strictHit = true;
    }

    return (strict && strictHit) ? 1 : 0;
}

} // namespace

int main(int argc, char** argv) {
    bool quiet = false, strict = false;
    enum { AUTO, ON, OFF } color = AUTO;
    std::vector<std::string> files;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "-h" || a == "--help") { printUsage(argv[0]); return 0; }
        else if (a == "-q" || a == "--quiet") quiet = true;
        else if (a == "-s" || a == "--strict") strict = true;
        else if (a == "--no-color") color = OFF;
        else if (a == "--color") color = ON;
        else files.push_back(a);
    }

    if (color == ON || (color == AUTO && ISATTY(FILENO(stdout)))) enableColor();

    if (files.empty()) { printUsage(argv[0]); return 2; }
    printBanner();

    int worst = 0;
    for (const auto& f : files) {
        int rc = analyzeFile(f, quiet, strict);
        if (rc > worst) worst = rc;
    }
    return worst;
}
