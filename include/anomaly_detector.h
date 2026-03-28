#pragma once

#include "log_entries.h"
#include "unified_timeline.h"
#include "../third_party/nlohmann/json.hpp"
#include <vector>
#include <string>
#include <map>
#include <set>
#include <functional>
#include <memory>
#include <mutex>

namespace log_analyzer {

using json = nlohmann::json;

// ============================================================================
// Anomaly Detector Interface
// ============================================================================
class IAnomalyDetector {
public:
    virtual ~IAnomalyDetector() = default;
    virtual std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const = 0;
    virtual std::string name() const = 0;
    
    // Load configuration from JSON array
    virtual void load_config(const json& config) = 0;
};

// ============================================================================
// DetectorFactory — Factory Pattern for anomaly detectors
// ============================================================================
class DetectorFactory {
public:
    using FactoryFn = std::function<std::unique_ptr<IAnomalyDetector>()>;

    static DetectorFactory& instance() {
        static DetectorFactory factory_instance;
        return factory_instance;
    }

    bool register_factory(const std::string& config_key, FactoryFn factory) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (factories_.count(config_key)) return false;
        factories_[config_key] = std::move(factory);
        return true;
    }

    std::unique_ptr<IAnomalyDetector> create(const std::string& config_key) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = factories_.find(config_key);
        if (it != factories_.end()) {
            return it->second();
        }
        return nullptr;
    }

    std::vector<std::string> registered_keys() const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> keys;
        keys.reserve(factories_.size());
        for (const auto& [key, _] : factories_) {
            keys.push_back(key);
        }
        return keys;
    }

private:
    DetectorFactory() = default;
    mutable std::mutex mutex_;
    std::map<std::string, FactoryFn> factories_;
};

#define REGISTER_DETECTOR_FACTORY(DetectorClass, ConfigKey) \
    inline bool _registered_##DetectorClass = \
        log_analyzer::DetectorFactory::instance().register_factory( \
            ConfigKey, \
            [](){ return std::make_unique<DetectorClass>(); } \
        )

// ============================================================================
// Signal Anomaly Detector — addresses Challenge #4 (Signal anomalies)
//
// Detects:
// 1. Range violation: signal value outside [min, max]
// 2. Spike: |delta| between consecutive samples > threshold
// 3. Freeze: signal unchanged for > N consecutive samples / duration
// ============================================================================
struct SignalRule {
    std::string signal_name;        // Signal to monitor (e.g., "VehicleSpeed")
    std::string source_event_type;  // Event type on timeline (e.g., "vehicle_speed")
    std::string value_property;     // Property key in UnifiedEvent (e.g., "value")
    double min_value = 0.0;         // Minimum valid value
    double max_value = 0.0;         // Maximum valid value
    double spike_threshold = 0.0;   // Max allowed delta between consecutive samples
    double freeze_duration_s = 0.0; // Max allowed duration with same value (seconds)
    int freeze_sample_count = 0;    // Max allowed consecutive same-value samples
};

class SignalAnomalyDetector : public IAnomalyDetector {
public:
    void add_rule(const SignalRule& rule);
    void load_config(const json& config) override;
    std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const override;
    std::string name() const override { return "SignalAnomalyDetector"; }

private:
    std::vector<SignalRule> rules_;
};
REGISTER_DETECTOR_FACTORY(SignalAnomalyDetector, "signal_rules");

// ============================================================================
// Sequence Anomaly Detector — addresses Challenge #4 (Sequence anomalies)
//
// Uses FSM (Finite State Machine) to detect invalid state transitions.
// Example: Door unlocked while vehicle is driving → ANOMALY
// ============================================================================
struct StateTransition {
    std::string from_state;
    std::string to_state;
    std::string trigger_event_type;    // Event type that causes transition
    std::string trigger_condition_key; // Property key to check
    std::string trigger_condition_val; // Expected property value
};

struct SequenceRule {
    std::string name;                           // Rule name (e.g., "DoorLockFSM")
    std::string initial_state;                  // Initial state
    std::vector<StateTransition> transitions;   // Valid transitions
    // Invalid transitions: any transition not in the list is considered anomalous
};

class SequenceAnomalyDetector : public IAnomalyDetector {
public:
    void add_rule(const SequenceRule& rule);
    void load_config(const json& config) override;
    std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const override;
    std::string name() const override { return "SequenceAnomalyDetector"; }

private:
    std::vector<SequenceRule> rules_;

    // Try to find a matching transition for the current state and event
    const StateTransition* find_transition(const SequenceRule& rule,
                                            const std::string& current_state,
                                            const UnifiedEvent& event) const;
};
REGISTER_DETECTOR_FACTORY(SequenceAnomalyDetector, "sequence_rules");

// ============================================================================
// Timing Anomaly Detector — addresses Challenge #4 (Timing anomalies)
//
// Detects:
// 1. Message loss: gap between messages of same type > expected_period * tolerance
// 2. Jitter: standard deviation of intervals > threshold
// ============================================================================
struct TimingRule {
    std::string event_type;            // Event type to monitor
    std::string source_type;           // Source type filter (e.g., "CAN")
    double expected_period_s = 0.0;    // Expected period between messages (seconds)
    double tolerance_factor = 2.0;     // Gap > period * tolerance → message loss
    double max_jitter_s = 0.0;        // Max allowed std deviation of intervals
    std::string filter_property_key;   // Optional: filter by property
    std::string filter_property_value; // Optional: filter by property value
};

class TimingAnomalyDetector : public IAnomalyDetector {
public:
    void add_rule(const TimingRule& rule);
    void load_config(const json& config) override;
    std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const override;
    std::string name() const override { return "TimingAnomalyDetector"; }

private:
    std::vector<TimingRule> rules_;
};
REGISTER_DETECTOR_FACTORY(TimingAnomalyDetector, "timing_rules");

// ============================================================================
// Consistency Anomaly Detector — addresses Challenge #4 (Consistency anomalies)
//
// Detects mismatches between the same data reported by different sources
// within a configurable time window.
// Example: CAN says door=unlocked, MQTT says door=locked → mismatch
// ============================================================================
struct ConsistencyMapping {
    std::string data_name;             // Semantic data name (e.g., "door_status")

    // Source A
    std::string source_a_type;         // e.g., "CAN"
    std::string source_a_event_type;   // e.g., "door_status"
    std::string source_a_value_key;    // Property key for the value
    // Value mapping: raw_value -> semantic_value
    std::map<std::string, std::string> source_a_value_map;

    // Source B
    std::string source_b_type;         // e.g., "MQTT"
    std::string source_b_event_type;   // e.g., "door_status_mqtt"
    std::string source_b_value_key;    // Property key for the value
    std::map<std::string, std::string> source_b_value_map;

    double time_window_s = 1.0;        // Time window for comparison (seconds)
    bool is_numeric = false;
    double numeric_tolerance = 0.0;
};

class ConsistencyAnomalyDetector : public IAnomalyDetector {
public:
    void add_mapping(const ConsistencyMapping& mapping);
    void load_config(const json& config) override;
    std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const override;
    std::string name() const override { return "ConsistencyAnomalyDetector"; }

private:
    std::vector<ConsistencyMapping> mappings_;
};
REGISTER_DETECTOR_FACTORY(ConsistencyAnomalyDetector, "consistency_rules");

// ============================================================================
// DLT Error Detector — detects DLT error/fatal level logs
// ============================================================================
class DLTErrorDetector : public IAnomalyDetector {
public:
    void load_config(const json& config) override {} // No config needed
    std::vector<Anomaly> detect(const UnifiedTimeline& timeline) const override;
    std::string name() const override { return "DLTErrorDetector"; }
};
REGISTER_DETECTOR_FACTORY(DLTErrorDetector, "dlt_error_rules");

} // namespace log_analyzer
