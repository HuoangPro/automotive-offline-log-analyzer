#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace log_analyzer {

// ============================================================================
// Base log entry — all log types share a timestamp and source type
// ============================================================================
struct LogEntry {
    double timestamp = 0.0;        // Seconds (relative or absolute)
    std::string source_type;       // "CAN", "DLT", "MQTT", "BACKEND"

    virtual ~LogEntry() = default;
};

// ============================================================================
// CAN Log Entry — fields from CAN 2.0 spec / CANoe log format
// ============================================================================
struct CANLogEntry : public LogEntry {
    uint32_t id = 0;               // CAN Message ID (11-bit or 29-bit)
    int channel = 1;               // CAN channel (1, 2, ...)
    bool is_extended = false;      // True if 29-bit extended ID
    int dlc = 0;                   // Data Length Code (0-8)
    std::vector<uint8_t> data;     // Raw data bytes
    std::string direction = "Rx";  // "Rx" or "Tx"

    // Decoded signals (populated after CAN DB decoding)
    // key: signal_name, value: physical_value
    std::map<std::string, double> decoded_signals;

    CANLogEntry() { source_type = "CAN"; }
};

// ============================================================================
// DLT Log Entry — fields from AUTOSAR DLT specification
// ============================================================================
struct DLTLogEntry : public LogEntry {
    std::string ecu_id;            // ECU identifier (4 chars, Standard Header)
    std::string app_id;            // Application ID (4 chars, Extended Header)
    std::string ctx_id;            // Context ID (4 chars, Extended Header)
    int session_id = 0;            // Session identifier (Standard Header)
    std::string msg_type;          // "log", "trace", "control", "network_trace" (MSTP)
    std::string log_level;         // "fatal","error","warn","info","debug","verbose" (MTIN)
    int counter = 0;               // Message counter 0-255 (Standard Header)
    std::string payload;           // Log message content (Payload segment)

    DLTLogEntry() { source_type = "DLT"; }
};

// ============================================================================
// MQTT Log Entry — fields from MQTT protocol spec
// ============================================================================
struct MQTTLogEntry : public LogEntry {
    std::string topic;             // MQTT topic (PUBLISH variable header)
    std::string payload;           // Message payload (PUBLISH payload, can be JSON)
    int qos = 0;                   // QoS level: 0, 1, or 2 (fixed header)
    std::string direction;         // "publish" or "receive" (application layer)

    // Note: timestamp is NOT part of MQTT protocol header.
    // It is recorded by the application layer when capturing the log.

    MQTTLogEntry() { source_type = "MQTT"; }
};

// ============================================================================
// Backend Log Entry — common backend logging fields
// ============================================================================
struct BackendLogEntry : public LogEntry {
    std::string level;             // "ERROR", "WARN", "INFO", "DEBUG"
    std::string service;           // Service name
    std::string endpoint;          // API endpoint (if applicable)
    std::string request_id;        // Request correlation ID
    std::string message;           // Log message content
    int response_code = 0;         // HTTP status code (if applicable)

    BackendLogEntry() { source_type = "BACKEND"; }
};

// ============================================================================
// Unified Event — normalized event on the unified timeline
// ============================================================================
struct UnifiedEvent {
    double normalized_timestamp = 0.0;  // Timestamp after time synchronization
    std::string source_type;            // Original source: "CAN", "DLT", "MQTT", "BACKEND"
    std::string event_type;             // Semantic event type (e.g., "vehicle_speed", "door_status")
    std::string description;            // Human-readable description
    std::map<std::string, std::string> properties;  // Key-value properties

    bool operator<(const UnifiedEvent& other) const {
        return normalized_timestamp < other.normalized_timestamp;
    }
};

// ============================================================================
// Anomaly — detected anomaly
// ============================================================================
enum class AnomalySeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

enum class AnomalyType {
    SIGNAL_RANGE,           // Signal value out of valid range
    SIGNAL_SPIKE,           // Sudden jump in signal value
    SIGNAL_FREEZE,          // Signal stuck at same value
    SEQUENCE_VIOLATION,     // Invalid state transition
    TIMING_MESSAGE_LOSS,    // Expected message missing
    TIMING_JITTER,          // Message interval too irregular
    CONSISTENCY_MISMATCH,   // Cross-source data mismatch
    DLT_ERROR               // DLT error/fatal log detected
};

struct Anomaly {
    AnomalyType type;
    AnomalySeverity severity;
    double timestamp = 0.0;
    std::string description;
    std::vector<UnifiedEvent> related_events;

    std::string type_to_string() const;
    std::string severity_to_string() const;
};


} // namespace log_analyzer
