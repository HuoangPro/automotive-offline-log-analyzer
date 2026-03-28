#pragma once

#include "log_entries.h"
#include <string>
#include <map>
#include <vector>

namespace log_analyzer {

// ============================================================================
// Time Synchronizer — addresses Challenge #1: Time Synchronization
//
// Different log sources use different time bases:
// - CAN log: relative time from CANoe start
// - DLT log: monotonic clock or system clock
// - MQTT log: epoch time (application layer)
// - Backend log: ISO 8601 timestamp
//
// Solution: Apply configurable offset per source to align all timestamps.
// normalized_timestamp = original_timestamp + offset[source_type]
// ============================================================================
class TimeSynchronizer {
public:
    // Set time offset for a specific source type
    // The offset is ADDED to the original timestamp
    void set_offset(const std::string& source_type, double offset_seconds);

    // Get configured offset for a source type
    double get_offset(const std::string& source_type) const;

    // Load offsets from JSON config file
    bool load_config(const std::string& filepath);

    // Apply offset to a single timestamp
    double synchronize(const std::string& source_type, double original_timestamp) const;

    // Apply offset to a vector of CAN entries (modifies in-place)
    void synchronize_can(std::vector<CANLogEntry>& entries) const;

    // Apply offset to a vector of DLT entries (modifies in-place)
    void synchronize_dlt(std::vector<DLTLogEntry>& entries) const;

    // Apply offset to a vector of MQTT entries (modifies in-place)
    void synchronize_mqtt(std::vector<MQTTLogEntry>& entries) const;

    // Apply offset to a vector of Backend entries (modifies in-place)
    void synchronize_backend(std::vector<BackendLogEntry>& entries) const;

private:
    std::map<std::string, double> offsets_;  // source_type -> offset_seconds
};

} // namespace log_analyzer
