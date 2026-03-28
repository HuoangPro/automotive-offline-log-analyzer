#pragma once

#include "log_entries.h"
#include <vector>
#include <string>
#include <ostream>

namespace log_analyzer {

// ============================================================================
// Anomaly Report Generator — formats and outputs anomaly detection results
// ============================================================================
class AnomalyReport {
public:
    // Add anomalies to the report
    void add_anomalies(const std::vector<Anomaly>& anomalies);

    // Get all anomalies sorted by timestamp
    std::vector<Anomaly> get_sorted_anomalies() const;

    // Get anomalies filtered by severity
    std::vector<Anomaly> get_by_severity(AnomalySeverity severity) const;

    // Get anomalies filtered by type
    std::vector<Anomaly> get_by_type(AnomalyType type) const;

    // Get summary statistics
    struct Summary {
        int total_anomalies = 0;
        int critical_count = 0;
        int high_count = 0;
        int medium_count = 0;
        int low_count = 0;
        std::map<AnomalyType, int> type_counts;
    };
    Summary get_summary() const;

    // Print report to output stream
    void print(std::ostream& os) const;

    // Get total anomaly count
    size_t total_count() const { return anomalies_.size(); }

private:
    std::vector<Anomaly> anomalies_;
};

} // namespace log_analyzer
