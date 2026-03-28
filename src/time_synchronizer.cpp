#include "time_synchronizer.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>

using json = nlohmann::json;

namespace log_analyzer {

void TimeSynchronizer::set_offset(const std::string& source_type, double offset_seconds) {
    offsets_[source_type] = offset_seconds;
}

double TimeSynchronizer::get_offset(const std::string& source_type) const {
    auto it = offsets_.find(source_type);
    if (it != offsets_.end()) {
        return it->second;
    }
    return 0.0;  // No offset configured → no adjustment
}

bool TimeSynchronizer::load_config(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    try {
        json j;
        file >> j;

        if (j.contains("time_offsets") && j["time_offsets"].is_object()) {
            for (auto& [key, val] : j["time_offsets"].items()) {
                offsets_[key] = val.get<double>();
            }
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

double TimeSynchronizer::synchronize(const std::string& source_type,
                                      double original_timestamp) const {
    return original_timestamp + get_offset(source_type);
}

void TimeSynchronizer::synchronize_can(std::vector<CANLogEntry>& entries) const {
    double offset = get_offset("CAN");
    for (auto& entry : entries) {
        entry.timestamp += offset;
    }
}

void TimeSynchronizer::synchronize_dlt(std::vector<DLTLogEntry>& entries) const {
    double offset = get_offset("DLT");
    for (auto& entry : entries) {
        entry.timestamp += offset;
    }
}

void TimeSynchronizer::synchronize_mqtt(std::vector<MQTTLogEntry>& entries) const {
    double offset = get_offset("MQTT");
    for (auto& entry : entries) {
        entry.timestamp += offset;
    }
}

void TimeSynchronizer::synchronize_backend(std::vector<BackendLogEntry>& entries) const {
    double offset = get_offset("BACKEND");
    for (auto& entry : entries) {
        entry.timestamp += offset;
    }
}

} // namespace log_analyzer
