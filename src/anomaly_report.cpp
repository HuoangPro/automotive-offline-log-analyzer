#include "anomaly_report.h"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace log_analyzer {

void AnomalyReport::add_anomalies(const std::vector<Anomaly>& anomalies) {
    anomalies_.insert(anomalies_.end(), anomalies.begin(), anomalies.end());
}

std::vector<Anomaly> AnomalyReport::get_sorted_anomalies() const {
    auto sorted = anomalies_;
    std::sort(sorted.begin(), sorted.end(),
              [](const Anomaly& a, const Anomaly& b) {
                  return a.timestamp < b.timestamp;
              });
    return sorted;
}

std::vector<Anomaly> AnomalyReport::get_by_severity(AnomalySeverity severity) const {
    std::vector<Anomaly> result;
    for (const auto& a : anomalies_) {
        if (a.severity == severity) {
            result.push_back(a);
        }
    }
    return result;
}

std::vector<Anomaly> AnomalyReport::get_by_type(AnomalyType type) const {
    std::vector<Anomaly> result;
    for (const auto& a : anomalies_) {
        if (a.type == type) {
            result.push_back(a);
        }
    }
    return result;
}

AnomalyReport::Summary AnomalyReport::get_summary() const {
    Summary s;
    s.total_anomalies = static_cast<int>(anomalies_.size());
    for (const auto& a : anomalies_) {
        switch (a.severity) {
            case AnomalySeverity::CRITICAL: s.critical_count++; break;
            case AnomalySeverity::HIGH:     s.high_count++; break;
            case AnomalySeverity::MEDIUM:   s.medium_count++; break;
            case AnomalySeverity::LOW:      s.low_count++; break;
        }
        s.type_counts[a.type]++;
    }
    return s;
}

void AnomalyReport::print(std::ostream& os) const {
    os << "\n";
    os << "===============================================================================\n";
    os << "                    AUTOMOTIVE OFFLINE LOG ANALYZER REPORT                      \n";
    os << "===============================================================================\n\n";

    // Summary
    auto summary = get_summary();
    os << "--- SUMMARY ---\n";
    os << "  Total anomalies: " << summary.total_anomalies << "\n";
    os << "  CRITICAL: " << summary.critical_count << "\n";
    os << "  HIGH:     " << summary.high_count << "\n";
    os << "  MEDIUM:   " << summary.medium_count << "\n";
    os << "  LOW:      " << summary.low_count << "\n\n";

    os << "  By type:\n";
    for (const auto& [type, count] : summary.type_counts) {
        Anomaly temp;
        temp.type = type;
        os << "    " << std::setw(25) << std::left << temp.type_to_string()
           << ": " << count << "\n";
    }
    os << "\n";

    // Detailed anomalies sorted by timestamp
    auto sorted = get_sorted_anomalies();
    os << "--- DETAILED ANOMALIES (sorted by time) ---\n\n";

    int idx = 1;
    for (const auto& a : sorted) {
        os << "  [" << idx++ << "] ";
        os << "[" << a.severity_to_string() << "] ";
        os << "[" << a.type_to_string() << "] ";
        os << "@ t=" << std::fixed << std::setprecision(3) << a.timestamp << "s\n";
        os << "      " << a.description << "\n";
        if (!a.related_events.empty()) {
            os << "      Related events:\n";
            for (const auto& e : a.related_events) {
                os << "        - [" << e.source_type << "] @ t="
                   << std::fixed << std::setprecision(3) << e.normalized_timestamp
                   << "s: " << e.description << "\n";
            }
        }
        os << "\n";
    }

    os << "===============================================================================\n";
}

} // namespace log_analyzer
