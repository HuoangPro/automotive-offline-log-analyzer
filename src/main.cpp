#include "analyzer_engine.h"
#include <iostream>
#include <string>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

void print_usage(const char* program) {
    std::cout << "Automotive Offline Log Analyzer\n\n";
    std::cout << "Usage: " << program << " <data_directory>\n\n";
    std::cout << "The analyzer auto-discovers log files using registered parsers.\n";
    std::cout << "Registered parser types:\n";

    auto& registry = log_analyzer::ParserRegistry::instance();
    for (const auto& type : registry.registered_types()) {
        auto parser = registry.get(type);
        std::cout << "  " << type << " -> " << parser->default_filename() << "\n";
    }

    std::cout << "\nAdditional files:\n";
    std::cout << "  can_database.json  - CAN signal database (DBC equivalent)\n";
    std::cout << "  anomaly_rules.json - Anomaly detection rules configuration\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string data_dir = argv[1];

    // Ensure trailing separator
    if (data_dir.back() != '/' && data_dir.back() != '\\') {
        data_dir += "/";
    }

    log_analyzer::AnalyzerEngine engine;

    // Auto-discover log files using ParserRegistry
    std::cout << "Scanning data directory: " << data_dir << "\n";

    auto& registry = log_analyzer::ParserRegistry::instance();
    for (const auto& source_type : registry.registered_types()) {
        auto parser = registry.get(source_type);
        std::string filename = parser->default_filename();
        std::string path = data_dir + filename;

        if (fs::exists(path)) {
            engine.add_log_file(source_type, path);
            std::cout << "  Found: " << filename << " [" << source_type << "]\n";
        } else {
            std::cout << "  Missing: " << filename << " (" << source_type << " — skipping)\n";
        }
    }

    // Special config files
    auto set_if_exists = [&](const std::string& filename, auto setter) {
        std::string path = data_dir + filename;
        if (fs::exists(path)) {
            (engine.*setter)(path);
            std::cout << "  Found: " << filename << "\n";
        } else {
            std::cout << "  Missing: " << filename << " (skipping)\n";
        }
    };

    set_if_exists("can_database.json", &log_analyzer::AnalyzerEngine::set_can_database);
    set_if_exists("anomaly_rules.json", &log_analyzer::AnalyzerEngine::set_anomaly_rules);

    std::cout << "\n";

    // Run analysis
    auto report = engine.run();
    
    // Save unified log
    engine.save_unified_timeline(data_dir + "out_unified_log.json");

    // Print results
    std::ofstream ofs(data_dir + "out_anormaly.report");
    report.print(ofs);

    // Return non-zero if critical anomalies found
    auto summary = report.get_summary();
    if (summary.critical_count > 0) {
        std::cout << "\n[!!!] " << summary.critical_count
                  << " CRITICAL anomalies detected!\n";
        return 2;
    }

    return 0;
}
