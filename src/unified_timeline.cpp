#include "unified_timeline.h"
#include "parsers.h"
#include "../third_party/nlohmann/json.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>

using json = nlohmann::json;

namespace log_analyzer {

// ============================================================================
// Generic API — accepts pre-converted events from any ILogParser
// ============================================================================
void UnifiedTimeline::add_events(const std::vector<UnifiedEvent>& events) {
    events_.insert(events_.end(), events.begin(), events.end());
    is_sorted_ = false;
}

// ============================================================================
// Legacy typed APIs — delegate to parser to_events() for conversion
// These are kept for backward compatibility with existing test code.
// ============================================================================
void UnifiedTimeline::add_can_events(const std::vector<CANLogEntry>& entries) {
    CANParser parser;
    for (const auto& entry : entries) {
        // Directly build events using same logic as CANParser::to_events
        // (CANParser::to_events is private, so we replicate the logic here
        //  to maintain backward compat without coupling)

        for (const auto& [sig_name, sig_value] : entry.decoded_signals) {
            UnifiedEvent event;
            event.normalized_timestamp = entry.timestamp;
            event.source_type = "CAN";

            std::string event_type = sig_name;
            std::transform(event_type.begin(), event_type.end(), event_type.begin(),
                          [](char c) { return std::tolower(c); });
            event.event_type = event_type;

            std::ostringstream desc;
            desc << "CAN [0x" << std::hex << entry.id << std::dec << "] "
                 << sig_name << " = " << sig_value;
            event.description = desc.str();

            event.properties["can_id"] = std::to_string(entry.id);
            event.properties["signal_name"] = sig_name;
            event.properties["value"] = std::to_string(sig_value);
            event.properties["channel"] = std::to_string(entry.channel);

            events_.push_back(event);
        }

        UnifiedEvent raw_event;
        raw_event.normalized_timestamp = entry.timestamp;
        raw_event.source_type = "CAN";
        raw_event.event_type = "can_message";

        std::ostringstream desc;
        desc << "CAN msg 0x" << std::hex << entry.id << std::dec
             << " DLC=" << entry.dlc;
        raw_event.description = desc.str();
        raw_event.properties["can_id"] = std::to_string(entry.id);
        raw_event.properties["dlc"] = std::to_string(entry.dlc);

        events_.push_back(raw_event);
    }

    is_sorted_ = false;
}

void UnifiedTimeline::add_dlt_events(const std::vector<DLTLogEntry>& entries) {
    for (const auto& entry : entries) {
        UnifiedEvent event;
        event.normalized_timestamp = entry.timestamp;
        event.source_type = "DLT";
        event.event_type = "dlt_" + entry.log_level;

        std::ostringstream desc;
        desc << "DLT [" << entry.ecu_id << "/" << entry.app_id << "/"
             << entry.ctx_id << "] " << entry.log_level << ": " << entry.payload;
        event.description = desc.str();

        event.properties["ecu_id"] = entry.ecu_id;
        event.properties["app_id"] = entry.app_id;
        event.properties["ctx_id"] = entry.ctx_id;
        event.properties["log_level"] = entry.log_level;
        event.properties["msg_type"] = entry.msg_type;
        event.properties["payload"] = entry.payload;

        events_.push_back(event);
    }

    is_sorted_ = false;
}

void UnifiedTimeline::add_mqtt_events(const std::vector<MQTTLogEntry>& entries) {
    for (const auto& entry : entries) {
        UnifiedEvent event;
        event.normalized_timestamp = entry.timestamp;
        event.source_type = "MQTT";

        std::string topic = entry.topic;
        size_t last_slash = topic.rfind('/');
        size_t second_last = (last_slash != std::string::npos) ?
                              topic.rfind('/', last_slash - 1) : std::string::npos;
        std::string event_type = "mqtt_message";
        if (last_slash != std::string::npos && second_last != std::string::npos) {
            std::string seg1 = topic.substr(second_last + 1, last_slash - second_last - 1);
            std::string seg2 = topic.substr(last_slash + 1);
            event_type = seg1 + "_" + seg2 + "_mqtt";
        } else if (last_slash != std::string::npos) {
            event_type = topic.substr(last_slash + 1) + "_mqtt";
        }
        event.event_type = event_type;

        event.description = "MQTT [" + entry.topic + "] " + entry.payload;

        event.properties["topic"] = entry.topic;
        event.properties["payload"] = entry.payload;
        event.properties["qos"] = std::to_string(entry.qos);
        event.properties["direction"] = entry.direction;

        try {
            auto payload_json = json::parse(entry.payload);
            for (auto& [key, val] : payload_json.items()) {
                if (val.is_string()) {
                    event.properties["mqtt_" + key] = val.get<std::string>();
                } else if (val.is_boolean()) {
                    event.properties["mqtt_" + key] = val.get<bool>() ? "true" : "false";
                } else if (val.is_number()) {
                    event.properties["mqtt_" + key] = std::to_string(val.get<double>());
                }
            }
        } catch (...) {
        }

        events_.push_back(event);
    }

    is_sorted_ = false;
}

void UnifiedTimeline::add_backend_events(const std::vector<BackendLogEntry>& entries) {
    for (const auto& entry : entries) {
        UnifiedEvent event;
        event.normalized_timestamp = entry.timestamp;
        event.source_type = "BACKEND";
        event.event_type = "backend_" + entry.level;

        event.description = "BACKEND [" + entry.service + "] " + entry.level +
                           ": " + entry.message;

        event.properties["level"] = entry.level;
        event.properties["service"] = entry.service;
        event.properties["endpoint"] = entry.endpoint;
        event.properties["request_id"] = entry.request_id;
        event.properties["message"] = entry.message;
        event.properties["response_code"] = std::to_string(entry.response_code);

        events_.push_back(event);
    }

    is_sorted_ = false;
}

void UnifiedTimeline::build() {
    std::stable_sort(events_.begin(), events_.end());
    is_sorted_ = true;
}

std::vector<UnifiedEvent> UnifiedTimeline::query_time_range(double start, double end) const {
    std::vector<UnifiedEvent> result;
    for (const auto& event : events_) {
        if (event.normalized_timestamp >= start && event.normalized_timestamp <= end) {
            result.push_back(event);
        }
    }
    return result;
}

std::vector<UnifiedEvent> UnifiedTimeline::query_by_source(
    const std::string& source_type, double start, double end) const {

    std::vector<UnifiedEvent> result;
    for (const auto& event : events_) {
        if (event.source_type == source_type) {
            if (start >= 0 && event.normalized_timestamp < start) continue;
            if (end >= 0 && event.normalized_timestamp > end) continue;
            result.push_back(event);
        }
    }
    return result;
}

std::vector<UnifiedEvent> UnifiedTimeline::query_by_event_type(
    const std::string& event_type, double start, double end) const {

    std::vector<UnifiedEvent> result;
    for (const auto& event : events_) {
        if (event.event_type == event_type) {
            if (start >= 0 && event.normalized_timestamp < start) continue;
            if (end >= 0 && event.normalized_timestamp > end) continue;
            result.push_back(event);
        }
    }
    return result;
}

} // namespace log_analyzer
