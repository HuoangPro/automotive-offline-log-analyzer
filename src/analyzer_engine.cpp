#include "analyzer_engine.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

namespace log_analyzer {

AnalyzerEngine::AnalyzerEngine() = default;

// -- Generic log file registration --
void AnalyzerEngine::add_log_file(const std::string& source_type, const std::string& filepath) {
    log_files_[source_type] = filepath;
}

// -- Legacy convenience setters --
void AnalyzerEngine::set_can_log(const std::string& filepath)     { add_log_file("CAN", filepath); }
void AnalyzerEngine::set_dlt_log(const std::string& filepath)     { add_log_file("DLT", filepath); }
void AnalyzerEngine::set_mqtt_log(const std::string& filepath)    { add_log_file("MQTT", filepath); }
void AnalyzerEngine::set_backend_log(const std::string& filepath) { add_log_file("BACKEND", filepath); }
void AnalyzerEngine::set_can_database(const std::string& filepath) { can_db_path_ = filepath; }
void AnalyzerEngine::set_anomaly_rules(const std::string& filepath) { anomaly_rules_path_ = filepath; }

void AnalyzerEngine::add_detector(std::unique_ptr<IAnomalyDetector> detector) {
    detectors_.push_back(std::move(detector));
}

void AnalyzerEngine::load_anomaly_rules() {
    if (anomaly_rules_path_.empty()) return;

    std::ifstream file(anomaly_rules_path_);
    if (!file.is_open()) return;

    try {
        json j;
        file >> j;

        detectors_.clear();
        event_mapper_ = EventMapper(); // Reset event mapper

        // Load time offsets for TimeSynchronizer
        if (j.contains("time_offsets") && j["time_offsets"].is_object()) {
            for (auto& [key, val] : j["time_offsets"].items()) {
                time_sync_.set_offset(key, val.get<double>());
            }
        }

        // Load Event Mapping rules
        if (j.contains("event_mappings") && j["event_mappings"].is_array()) {
            event_mapper_.load_config(j["event_mappings"]);
        }

        // Auto-discover and load configured anomaly detectors using DetectorFactory
        auto& factory = DetectorFactory::instance();
        for (const auto& key : factory.registered_keys()) {
            if (j.contains(key) && j[key].is_array()) {
                auto detector = factory.create(key);
                if (detector) {
                    detector->load_config(j[key]);
                    detectors_.push_back(std::move(detector));
                }
            }
        }

        // Ensure DLTErrorDetector is always added backward-compatibly, since it requires no config rules
        detectors_.push_back(factory.create("dlt_error_rules"));

    } catch (const std::exception& e) {
        std::cerr << "Error loading anomaly rules: " << e.what() << std::endl;
    }
}

AnomalyReport AnalyzerEngine::run() {
    AnomalyReport report;

    // ========================================================================
    // Step 1: Load CAN Database (special case for CAN parser)
    // ========================================================================
    std::cout << "[1/5] Loading CAN database..." << std::endl;
    if (!can_db_path_.empty()) {
        if (can_db_.load(can_db_path_)) {
            std::cout << "  Loaded " << can_db_.get_messages().size() << " message definitions\n";
        } else {
            std::cerr << "  WARNING: Failed to load CAN database from " << can_db_path_ << "\n";
        }
    }

    // ========================================================================
    // Step 2: Load anomaly rules & Event Mapper config
    // ========================================================================
    std::cout << "[2/5] Loading anomaly rules..." << std::endl;
    load_anomaly_rules();
    std::cout << "  Loaded " << detectors_.size() << " detectors\n";

    // ========================================================================
    // Step 3: Parse all log files via ParserRegistry
    // ========================================================================
    std::cout << "[3/5] Parsing log files via registry..." << std::endl;

    auto& registry = ParserRegistry::instance();
    std::vector<UnifiedEvent> all_events;

    for (const auto& [source_type, filepath] : log_files_) {
        if (!registry.has(source_type)) {
            std::cerr << "  WARNING: No parser registered for source type '"
                      << source_type << "' — skipping " << filepath << "\n";
            continue;
        }

        // Get parser from registry
        auto parser = registry.get(source_type);

        // Special case: inject CAN database into CAN parser
        if (source_type == "CAN") {
            auto* can_parser = dynamic_cast<CANParser*>(parser.get());
            if (can_parser) {
                can_parser->set_can_database(&can_db_);
            }
        }

        // Parse to events
        auto events = parser->parse_to_events(filepath);
        
        // Defensive fix: Ensure events from a single source are strictly chronological
        // before time sync or mapping are applied.
        std::stable_sort(events.begin(), events.end(), [](const UnifiedEvent& a, const UnifiedEvent& b) {
            return a.normalized_timestamp < b.normalized_timestamp;
        });

        std::cout << "  " << source_type << ": " << events.size() << " events"
                  << " (parser: " << parser->source_type() << ")\n";

        // Apply time synchronization to events
        double offset = time_sync_.get_offset(source_type);
        if (offset != 0.0) {
            for (auto& event : events) {
                event.normalized_timestamp += offset;
            }
        }

        // Apply Event Mapping (Convert Regex raw payloads into structured properties)
        events = event_mapper_.map_events(events);

        all_events.insert(all_events.end(), events.begin(), events.end());
    }

    // ========================================================================
    // Step 4: Build unified timeline
    // ========================================================================
    std::cout << "[4/5] Building unified timeline..." << std::endl;
    timeline_ = UnifiedTimeline();
    timeline_.add_events(all_events);
    timeline_.build();
    std::cout << "  Timeline contains " << timeline_.size() << " events\n";

    // ========================================================================
    // Step 5: Run anomaly detectors
    // ========================================================================
    std::cout << "[5/5] Running anomaly detection..." << std::endl;
    for (const auto& detector : detectors_) {
        auto detected = detector->detect(timeline_);
        std::cout << "  " << detector->name() << ": " << detected.size() << " anomalies\n";
        report.add_anomalies(detected);
    }

    return report;
}

void AnalyzerEngine::save_unified_timeline(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "  ERROR: Failed to save unified log to " << filepath << "\n";
        return;
    }

    using ordered_json = nlohmann::ordered_json;
    file << "[" << std::endl;
    bool first = true;
    for (const auto& event : timeline_.get_events()) {
        if(!first) file << ",\n";
        else first = false;
        ordered_json e;
        e["timestamp"] = event.normalized_timestamp;
        e["source"] = event.source_type;
        e["type"] = event.event_type;
        
        ordered_json props = ordered_json::object();
        for (const auto& [k, v] : event.properties) {
            props[k] = v;
        }
        e["properties"] = props;
        e["description"] = event.description;
        file << e.dump();
    }
    file << "\n]" << std::endl;
    std::cout << "  Unified log saved (NDJSON format) to: " << filepath << "\n";
}

} // namespace log_analyzer
