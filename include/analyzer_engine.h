#pragma once

#include "log_entries.h"
#include "can_database.h"
#include "parsers.h"
#include "time_synchronizer.h"
#include "event_mapper.h"
#include "unified_timeline.h"
#include "anomaly_detector.h"
#include "anomaly_report.h"

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace log_analyzer {

// ============================================================================
// Analyzer Engine — orchestrates the full analysis pipeline
//
// Now uses ParserRegistry for source-agnostic log processing:
// - Engine discovers available parsers from the registry
// - Log files are mapped to parser by source type
// - New log sources can be added without modifying engine code
//
// Pipeline:
// 1. Load CAN Database (special-case: used by CAN parser)
// 2. Load anomaly rules from config and register detectors
// 3. Parse all log files → unified events (Synchronize & Map)
// 4. Build unified timeline (Global stable sort)
// 5. Run anomaly detectors
// 6. Generate report
// ============================================================================
class AnalyzerEngine {
public:
    AnalyzerEngine();

    // -- Generic log file registration --
    // Register a log file for a given source type (e.g., "CAN" → "path/to/can_log.json")
    void add_log_file(const std::string& source_type, const std::string& filepath);

    // -- Legacy convenience setters (map to add_log_file) --
    void set_can_log(const std::string& filepath);
    void set_dlt_log(const std::string& filepath);
    void set_mqtt_log(const std::string& filepath);
    void set_backend_log(const std::string& filepath);
    void set_can_database(const std::string& filepath);
    void set_anomaly_rules(const std::string& filepath);

    // Register anomaly detectors
    void add_detector(std::unique_ptr<IAnomalyDetector> detector);

    // Run the full analysis pipeline
    AnomalyReport run();

    // Access intermediate results
    const UnifiedTimeline& get_timeline() const { return timeline_; }

    // Save the fully processed and normalized timeline to a file
    void save_unified_timeline(const std::string& filepath) const;

private:
    // Log file mapping: source_type → filepath
    std::map<std::string, std::string> log_files_;

    // Special configs
    std::string can_db_path_;
    std::string anomaly_rules_path_;

    // Components
    CANDatabase can_db_;
    TimeSynchronizer time_sync_;
    EventMapper event_mapper_;
    UnifiedTimeline timeline_;

    // Detectors
    std::vector<std::unique_ptr<IAnomalyDetector>> detectors_;

    // Load anomaly rules from config and register detectors
    void load_anomaly_rules();
};

} // namespace log_analyzer
