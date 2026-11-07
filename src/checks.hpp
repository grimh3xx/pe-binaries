// PE-Binaries — evasion-artifact heuristics.
// Each check inspects a parsed Image and emits zero or more Findings.
#pragma once

#include "pe.hpp"
#include <string>
#include <vector>

namespace pes {

enum class Severity { Info, Low, Medium, High };

struct Finding {
    Severity    severity;
    std::string id;       // short stable tag, e.g. "BLOAT_OVERLAY"
    std::string title;
    std::string detail;
};

const char* severityName(Severity s);

// Run every heuristic over the image and return the findings, worst first.
std::vector<Finding> analyze(const Image& img);

// Weighted 0..100 risk score derived from the findings, plus a short label.
int riskScore(const std::vector<Finding>& findings);
const char* riskLabel(int score);

} // namespace pes
