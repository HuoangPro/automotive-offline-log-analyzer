#include "parsers.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iomanip>

using json = nlohmann::json;

namespace log_analyzer {

// ============================================================================
// ParserRegistry — Singleton + Registry Pattern implementation
// ============================================================================
ParserRegistry& ParserRegistry::instance() {
    static ParserRegistry registry;
    return registry;
}

bool ParserRegistry::register_parser(const std::string& source_type, FactoryFn factory) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (instances_.count(source_type)) {
        return false;  // Already registered
    }
    instances_[source_type] = factory();
    return true;
}

std::shared_ptr<ILogParser> ParserRegistry::get(const std::string& source_type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = instances_.find(source_type);
    if (it != instances_.end()) {
        return it->second;
    }
    return nullptr;
}

bool ParserRegistry::has(const std::string& source_type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return instances_.count(source_type) > 0;
}

std::vector<std::string> ParserRegistry::registered_types() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> types;
    types.reserve(instances_.size());
    for (const auto& [key, _] : instances_) {
        types.push_back(key);
    }
    return types;
}

std::vector<std::shared_ptr<ILogParser>> ParserRegistry::get_all() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<ILogParser>> parsers;
    for (const auto& [_, instance] : instances_) {
        parsers.push_back(instance);
    }
    return parsers;
}

void ParserRegistry::unregister_parser(const std::string& source_type) {
    std::lock_guard<std::mutex> lock(mutex_);
    instances_.erase(source_type);
}

void ParserRegistry::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    instances_.clear();
}

// Parsers automatically register themselves via inline macros in parsers.h

// ============================================================================
// CAN Parser
// ============================================================================
CANParser::CANParser(const CANDatabase* can_db) : can_db_(can_db) {}

std::vector<CANLogEntry> CANParser::parse(const std::string& filepath) const {
    std::vector<CANLogEntry> entries;

    std::ifstream file(filepath);
    if (!file.is_open()) {
        return entries;
    }

    try {
        json j;
        file >> j;

        if (!j.is_array()) {
            return entries;
        }

        for (const auto& item : j) {
            CANLogEntry entry;
            entry.timestamp = item.value("timestamp", 0.0);
            entry.id = item.value("id", 0u);
            entry.channel = item.value("channel", 1);
            entry.is_extended = item.value("is_extended", false);
            entry.dlc = item.value("dlc", 0);
            entry.direction = item.value("direction", "Rx");

            // Parse data array (hex bytes as integers)
            if (item.contains("data") && item["data"].is_array()) {
                for (const auto& byte_val : item["data"]) {
                    entry.data.push_back(static_cast<uint8_t>(byte_val.get<int>()));
                }
            }

            // Validate entry
            if (!validate(entry)) {
                continue;
            }

            // Decode signals if CAN database is available
            if (can_db_) {
                entry.decoded_signals = can_db_->decode_message(entry.id, entry.data);
            }

            entries.push_back(entry);
        }
    } catch (const std::exception&) {
        // Return what we have parsed so far
    }

    return entries;
}

bool CANParser::validate(const CANLogEntry& entry) {
    if (entry.timestamp < 0.0) return false;
    if (entry.dlc < 0 || entry.dlc > 8) return false;
    if (static_cast<int>(entry.data.size()) != entry.dlc) return false;
    return true;
}

std::vector<UnifiedEvent> CANParser::to_events(const CANLogEntry& entry) const {
    std::vector<UnifiedEvent> events;

    // One event per decoded signal
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

        events.push_back(event);
    }

    // Raw CAN message event (for timing analysis)
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

    events.push_back(raw_event);

    return events;
}

std::vector<UnifiedEvent> CANParser::parse_to_events(const std::string& filepath) const {
    auto entries = parse(filepath);
    std::vector<UnifiedEvent> all_events;
    for (const auto& entry : entries) {
        auto events = to_events(entry);
        all_events.insert(all_events.end(), events.begin(), events.end());
    }
    return all_events;
}

// ============================================================================
// DLT Parser
// ============================================================================
std::vector<DLTLogEntry> DLTParser::parse(const std::string& filepath) const {
    std::vector<DLTLogEntry> entries;

    std::ifstream file(filepath);
    if (!file.is_open()) {
        return entries;
    }

    try {
        json j;
        file >> j;

        if (!j.is_array()) {
            return entries;
        }

        for (const auto& item : j) {
            DLTLogEntry entry;
            entry.timestamp = item.value("timestamp", 0.0);
            entry.ecu_id = item.value("ecu_id", "");
            entry.app_id = item.value("app_id", "");
            entry.ctx_id = item.value("ctx_id", "");
            entry.session_id = item.value("session_id", 0);
            entry.msg_type = item.value("msg_type", "log");
            entry.log_level = item.value("log_level", "info");
            entry.counter = item.value("counter", 0);
            entry.payload = item.value("payload", "");

            if (validate(entry)) {
                entries.push_back(entry);
            }
        }
    } catch (const std::exception&) {
    }

    return entries;
}

bool DLTParser::validate(const DLTLogEntry& entry) {
    if (entry.timestamp < 0.0) return false;
    if (entry.ecu_id.empty()) return false;
    if (entry.payload.empty()) return false;
    return true;
}

std::vector<UnifiedEvent> DLTParser::to_events(const DLTLogEntry& entry) const {
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

    return {event};
}

std::vector<UnifiedEvent> DLTParser::parse_to_events(const std::string& filepath) const {
    auto entries = parse(filepath);
    std::vector<UnifiedEvent> all_events;
    for (const auto& entry : entries) {
        auto events = to_events(entry);
        all_events.insert(all_events.end(), events.begin(), events.end());
    }
    return all_events;
}

// ============================================================================
// MQTT Parser
// ============================================================================
std::vector<MQTTLogEntry> MQTTParser::parse(const std::string& filepath) const {
    std::vector<MQTTLogEntry> entries;

    std::ifstream file(filepath);
    if (!file.is_open()) {
        return entries;
    }

    try {
        json j;
        file >> j;

        if (!j.is_array()) {
            return entries;
        }

        for (const auto& item : j) {
            MQTTLogEntry entry;
            entry.timestamp = item.value("timestamp", 0.0);
            entry.topic = item.value("topic", "");
            entry.payload = item.value("payload", "");
            entry.qos = item.value("qos", 0);
            entry.direction = item.value("direction", "publish");

            if (validate(entry)) {
                entries.push_back(entry);
            }
        }
    } catch (const std::exception&) {
    }

    return entries;
}

bool MQTTParser::validate(const MQTTLogEntry& entry) {
    if (entry.timestamp < 0.0) return false;
    if (entry.topic.empty()) return false;
    if (entry.qos < 0 || entry.qos > 2) return false;
    return true;
}

std::vector<UnifiedEvent> MQTTParser::to_events(const MQTTLogEntry& entry) const {
    UnifiedEvent event;
    event.normalized_timestamp = entry.timestamp;
    event.source_type = "MQTT";

    // Extract meaningful event type from topic
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

    // Try to parse JSON payload and extract key-value pairs
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
        // Payload is not JSON, that's OK
    }

    return {event};
}

std::vector<UnifiedEvent> MQTTParser::parse_to_events(const std::string& filepath) const {
    auto entries = parse(filepath);
    std::vector<UnifiedEvent> all_events;
    for (const auto& entry : entries) {
        auto events = to_events(entry);
        all_events.insert(all_events.end(), events.begin(), events.end());
    }
    return all_events;
}

// ============================================================================
// Backend Parser
// ============================================================================
std::vector<BackendLogEntry> BackendParser::parse(const std::string& filepath) const {
    std::vector<BackendLogEntry> entries;

    std::ifstream file(filepath);
    if (!file.is_open()) {
        return entries;
    }

    try {
        json j;
        file >> j;

        if (!j.is_array()) {
            return entries;
        }

        for (const auto& item : j) {
            BackendLogEntry entry;
            entry.timestamp = item.value("timestamp", 0.0);
            entry.level = item.value("level", "INFO");
            entry.service = item.value("service", "");
            entry.endpoint = item.value("endpoint", "");
            entry.request_id = item.value("request_id", "");
            entry.message = item.value("message", "");
            entry.response_code = item.value("response_code", 0);

            if (validate(entry)) {
                entries.push_back(entry);
            }
        }
    } catch (const std::exception&) {
    }

    return entries;
}

bool BackendParser::validate(const BackendLogEntry& entry) {
    if (entry.timestamp < 0.0) return false;
    if (entry.service.empty()) return false;
    if (entry.message.empty()) return false;
    return true;
}

std::vector<UnifiedEvent> BackendParser::to_events(const BackendLogEntry& entry) const {
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

    return {event};
}

std::vector<UnifiedEvent> BackendParser::parse_to_events(const std::string& filepath) const {
    auto entries = parse(filepath);
    std::vector<UnifiedEvent> all_events;
    for (const auto& entry : entries) {
        auto events = to_events(entry);
        all_events.insert(all_events.end(), events.begin(), events.end());
    }
    return all_events;
}

} // namespace log_analyzer
