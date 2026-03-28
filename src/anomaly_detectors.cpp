#include "anomaly_detector.h"
#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>

namespace log_analyzer {

// ============================================================================
// Signal Anomaly Detector
// ============================================================================
void SignalAnomalyDetector::add_rule(const SignalRule& rule) {
    rules_.push_back(rule);
}

void SignalAnomalyDetector::load_config(const json& config) {
    if (!config.is_array()) return;
    for (const auto& rule_json : config) {
        SignalRule rule;
        rule.signal_name = rule_json.value("signal_name", "");
        rule.source_event_type = rule_json.value("source_event_type", "");
        rule.value_property = rule_json.value("value_property", "value");
        rule.min_value = rule_json.value("min_value", 0.0);
        rule.max_value = rule_json.value("max_value", 0.0);
        rule.spike_threshold = rule_json.value("spike_threshold", 0.0);
        rule.freeze_duration_s = rule_json.value("freeze_duration_s", 0.0);
        rule.freeze_sample_count = rule_json.value("freeze_sample_count", 0);
        add_rule(rule);
    }
}

std::vector<Anomaly> SignalAnomalyDetector::detect(const UnifiedTimeline& timeline) const {
    std::vector<Anomaly> anomalies;

    for (const auto& rule : rules_) {
        // Get all events matching this rule's event type
        auto events = timeline.query_by_event_type(rule.source_event_type);
        if (events.empty()) continue;

        double prev_value = std::numeric_limits<double>::quiet_NaN();
        double freeze_start_time = -1.0;
        double freeze_value = std::numeric_limits<double>::quiet_NaN();
        int freeze_count = 0;

        for (size_t i = 0; i < events.size(); i++) {
            const auto& event = events[i];

            // Extract value from properties
            auto it = event.properties.find(rule.value_property);
            if (it == event.properties.end()) continue;

            double value;
            try {
                value = std::stod(it->second);
            } catch (...) {
                continue;
            }

            // --- Check 1: Range violation ---
            if (value < rule.min_value || value > rule.max_value) {
                Anomaly a;
                a.type = AnomalyType::SIGNAL_RANGE;
                a.severity = AnomalySeverity::HIGH;
                a.timestamp = event.normalized_timestamp;
                a.description = rule.signal_name + " value " + std::to_string(value) +
                               " out of range [" + std::to_string(rule.min_value) +
                               ", " + std::to_string(rule.max_value) + "]";
                a.related_events.push_back(event);
                anomalies.push_back(a);
            }

            // --- Check 2: Spike detection ---
            if (!std::isnan(prev_value) && rule.spike_threshold > 0.0) {
                double delta = std::abs(value - prev_value);
                if (delta > rule.spike_threshold) {
                    Anomaly a;
                    a.type = AnomalyType::SIGNAL_SPIKE;
                    a.severity = AnomalySeverity::HIGH;
                    a.timestamp = event.normalized_timestamp;
                    a.description = rule.signal_name + " spike: " +
                                   std::to_string(prev_value) + " -> " +
                                   std::to_string(value) + " (delta=" +
                                   std::to_string(delta) + " > threshold=" +
                                   std::to_string(rule.spike_threshold) + ")";
                    a.related_events.push_back(event);
                    if (i > 0) a.related_events.push_back(events[i-1]);
                    anomalies.push_back(a);
                }
            }

            // --- Check 3: Freeze detection ---
            if (!std::isnan(freeze_value) && std::abs(value - freeze_value) < 1e-9) {
                freeze_count++;

                // Check freeze by duration
                if (rule.freeze_duration_s > 0.0) {
                    double duration = event.normalized_timestamp - freeze_start_time;
                    if (duration >= rule.freeze_duration_s) {
                        // Only report once when threshold is first exceeded
                        if (freeze_count == 2 ||
                            (event.normalized_timestamp - freeze_start_time -
                             (events[i-1].normalized_timestamp - freeze_start_time))
                            < rule.freeze_duration_s * 0.5) {
                            // Check if we already reported this freeze
                            bool already_reported = false;
                            for (const auto& existing : anomalies) {
                                if (existing.type == AnomalyType::SIGNAL_FREEZE &&
                                    std::abs(existing.timestamp - freeze_start_time) < 0.001) {
                                    already_reported = true;
                                    break;
                                }
                            }
                            if (!already_reported) {
                                Anomaly a;
                                a.type = AnomalyType::SIGNAL_FREEZE;
                                a.severity = AnomalySeverity::MEDIUM;
                                a.timestamp = freeze_start_time;
                                a.description = rule.signal_name + " frozen at " +
                                               std::to_string(freeze_value) + " for " +
                                               std::to_string(duration) + "s (threshold=" +
                                               std::to_string(rule.freeze_duration_s) + "s)";
                                a.related_events.push_back(events[i]);
                                anomalies.push_back(a);
                            }
                        }
                    }
                }

                // Check freeze by sample count
                if (rule.freeze_sample_count > 0 && freeze_count >= rule.freeze_sample_count) {
                    bool already_reported = false;
                    for (const auto& existing : anomalies) {
                        if (existing.type == AnomalyType::SIGNAL_FREEZE &&
                            std::abs(existing.timestamp - freeze_start_time) < 0.001) {
                            already_reported = true;
                            break;
                        }
                    }
                    if (!already_reported) {
                        Anomaly a;
                        a.type = AnomalyType::SIGNAL_FREEZE;
                        a.severity = AnomalySeverity::MEDIUM;
                        a.timestamp = freeze_start_time;
                        a.description = rule.signal_name + " frozen at " +
                                       std::to_string(freeze_value) + " for " +
                                       std::to_string(freeze_count) + " samples (threshold=" +
                                       std::to_string(rule.freeze_sample_count) + ")";
                        a.related_events.push_back(events[i]);
                        anomalies.push_back(a);
                    }
                }
            } else {
                // Value changed, reset freeze tracking
                freeze_value = value;
                freeze_start_time = event.normalized_timestamp;
                freeze_count = 1;
            }

            prev_value = value;
        }
    }

    return anomalies;
}

// ============================================================================
// Sequence Anomaly Detector
// ============================================================================
void SequenceAnomalyDetector::add_rule(const SequenceRule& rule) {
    rules_.push_back(rule);
}

void SequenceAnomalyDetector::load_config(const json& config) {
    if (!config.is_array()) return;
    for (const auto& rule_json : config) {
        SequenceRule rule;
        rule.name = rule_json.value("name", "");
        rule.initial_state = rule_json.value("initial_state", "");
        if (rule_json.contains("transitions") && rule_json["transitions"].is_array()) {
            for (const auto& trans_json : rule_json["transitions"]) {
                StateTransition trans;
                trans.from_state = trans_json.value("from_state", "");
                trans.to_state = trans_json.value("to_state", "");
                trans.trigger_event_type = trans_json.value("trigger_event_type", "");
                trans.trigger_condition_key = trans_json.value("trigger_condition_key", "");
                trans.trigger_condition_val = trans_json.value("trigger_condition_val", "");
                rule.transitions.push_back(trans);
            }
        }
        add_rule(rule);
    }
}

const StateTransition* SequenceAnomalyDetector::find_transition(
    const SequenceRule& rule,
    const std::string& current_state,
    const UnifiedEvent& event) const {

    // Priority: specific transitions (with conditions) first, generic (no condition) last
    const StateTransition* generic_match = nullptr;

    for (const auto& trans : rule.transitions) {
        if (trans.from_state != current_state) continue;
        if (trans.trigger_event_type != event.event_type) continue;

        // Check condition if specified
        if (!trans.trigger_condition_key.empty()) {
            auto it = event.properties.find(trans.trigger_condition_key);
            if (it == event.properties.end()) continue;
            if (it->second != trans.trigger_condition_val) continue;
            // Specific match found — highest priority
            return &trans;
        } else {
            // Generic match (no condition) — keep as fallback
            if (!generic_match) {
                generic_match = &trans;
            }
        }
    }
    return generic_match;
}

std::vector<Anomaly> SequenceAnomalyDetector::detect(const UnifiedTimeline& timeline) const {
    std::vector<Anomaly> anomalies;

    for (const auto& rule : rules_) {
        std::string current_state = rule.initial_state;
        const auto& events = timeline.get_events();

        for (const auto& event : events) {
            // Check if this event is relevant to any transition from the current state
            bool is_relevant = false;
            for (const auto& trans : rule.transitions) {
                if (trans.trigger_event_type == event.event_type) {
                    // Check condition match
                    if (!trans.trigger_condition_key.empty()) {
                        auto it = event.properties.find(trans.trigger_condition_key);
                        if (it == event.properties.end()) continue;
                        if (it->second != trans.trigger_condition_val) continue;
                    }
                    is_relevant = true;
                    break;
                }
            }

            if (!is_relevant) continue;

            // Try to find a valid transition
            const StateTransition* trans = find_transition(rule, current_state, event);
            if (trans) {
                // Valid transition
                current_state = trans->to_state;
            } else {
                // No valid transition found → ANOMALY
                // But first check if ANY transition for this event type exists
                // (from a different state) to confirm it's a sequence violation
                bool event_type_exists = false;
                std::string expected_state;
                for (const auto& t : rule.transitions) {
                    if (t.trigger_event_type == event.event_type) {
                        if (!t.trigger_condition_key.empty()) {
                            auto it = event.properties.find(t.trigger_condition_key);
                            if (it == event.properties.end()) continue;
                            if (it->second != t.trigger_condition_val) continue;
                        }
                        event_type_exists = true;
                        expected_state = t.from_state;
                        break;
                    }
                }

                if (event_type_exists) {
                    Anomaly a;
                    a.type = AnomalyType::SEQUENCE_VIOLATION;
                    a.severity = AnomalySeverity::CRITICAL;
                    a.timestamp = event.normalized_timestamp;
                    a.description = "[" + rule.name + "] Invalid transition: event '" +
                                   event.event_type + "' in state '" + current_state +
                                   "' (expected state: '" + expected_state + "')";
                    a.related_events.push_back(event);
                    anomalies.push_back(a);
                }
            }
        }
    }

    return anomalies;
}

// ============================================================================
// Timing Anomaly Detector
// ============================================================================
void TimingAnomalyDetector::add_rule(const TimingRule& rule) {
    rules_.push_back(rule);
}

void TimingAnomalyDetector::load_config(const json& config) {
    if (!config.is_array()) return;
    for (const auto& rule_json : config) {
        TimingRule rule;
        rule.event_type = rule_json.value("event_type", "");
        rule.source_type = rule_json.value("source_type", "");
        rule.expected_period_s = rule_json.value("expected_period_s", 0.0);
        rule.tolerance_factor = rule_json.value("tolerance_factor", 2.0);
        rule.max_jitter_s = rule_json.value("max_jitter_s", 0.0);
        rule.filter_property_key = rule_json.value("filter_property_key", "");
        rule.filter_property_value = rule_json.value("filter_property_value", "");
        add_rule(rule);
    }
}

std::vector<Anomaly> TimingAnomalyDetector::detect(const UnifiedTimeline& timeline) const {
    std::vector<Anomaly> anomalies;

    for (const auto& rule : rules_) {
        // Get events matching this rule
        std::vector<UnifiedEvent> matched_events;
        for (const auto& event : timeline.get_events()) {
            if (event.event_type != rule.event_type) continue;
            if (!rule.source_type.empty() && event.source_type != rule.source_type) continue;

            // Apply optional property filter
            if (!rule.filter_property_key.empty()) {
                auto it = event.properties.find(rule.filter_property_key);
                if (it == event.properties.end()) continue;
                if (it->second != rule.filter_property_value) continue;
            }

            matched_events.push_back(event);
        }

        if (matched_events.size() < 2) continue;

        // Compute intervals between consecutive messages
        std::vector<double> intervals;
        for (size_t i = 1; i < matched_events.size(); i++) {
            double interval = matched_events[i].normalized_timestamp -
                             matched_events[i-1].normalized_timestamp;
            intervals.push_back(interval);

            // Check for message loss (gap too large)
            double max_allowed = rule.expected_period_s * rule.tolerance_factor;
            if (interval > max_allowed) {
                Anomaly a;
                a.type = AnomalyType::TIMING_MESSAGE_LOSS;
                a.severity = AnomalySeverity::MEDIUM;
                a.timestamp = matched_events[i-1].normalized_timestamp;
                a.description = rule.event_type + " message gap: " +
                               std::to_string(interval) + "s (expected period=" +
                               std::to_string(rule.expected_period_s) + "s, max allowed=" +
                               std::to_string(max_allowed) + "s)";
                a.related_events.push_back(matched_events[i-1]);
                a.related_events.push_back(matched_events[i]);
                anomalies.push_back(a);
            }
        }

        // Check jitter (standard deviation of intervals)
        if (rule.max_jitter_s > 0.0 && intervals.size() > 1) {
            double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) /
                         intervals.size();
            double sq_sum = 0.0;
            for (double interval : intervals) {
                sq_sum += (interval - mean) * (interval - mean);
            }
            double stddev = std::sqrt(sq_sum / intervals.size());

            if (stddev > rule.max_jitter_s) {
                Anomaly a;
                a.type = AnomalyType::TIMING_JITTER;
                a.severity = AnomalySeverity::MEDIUM;
                a.timestamp = matched_events.front().normalized_timestamp;
                a.description = rule.event_type + " jitter too high: stddev=" +
                               std::to_string(stddev) + "s (max allowed=" +
                               std::to_string(rule.max_jitter_s) + "s)";
                anomalies.push_back(a);
            }
        }
    }

    return anomalies;
}

// ============================================================================
// Consistency Anomaly Detector
// ============================================================================
void ConsistencyAnomalyDetector::add_mapping(const ConsistencyMapping& mapping) {
    mappings_.push_back(mapping);
}

void ConsistencyAnomalyDetector::load_config(const json& config) {
    if (!config.is_array()) return;
    for (const auto& rule_json : config) {
        ConsistencyMapping mapping;
        mapping.data_name = rule_json.value("data_name", "");
        mapping.source_a_type = rule_json.value("source_a_type", "");
        mapping.source_a_event_type = rule_json.value("source_a_event_type", "");
        mapping.source_a_value_key = rule_json.value("source_a_value_key", "");
        mapping.source_b_type = rule_json.value("source_b_type", "");
        mapping.source_b_event_type = rule_json.value("source_b_event_type", "");
        mapping.source_b_value_key = rule_json.value("source_b_value_key", "");
        mapping.time_window_s = rule_json.value("time_window_s", 1.0);
        mapping.is_numeric = rule_json.value("is_numeric", false);
        mapping.numeric_tolerance = rule_json.value("numeric_tolerance", 0.0);

        if (rule_json.contains("source_a_value_map")) {
            for (auto& [k, v] : rule_json["source_a_value_map"].items()) {
                mapping.source_a_value_map[k] = v.get<std::string>();
            }
        }
        if (rule_json.contains("source_b_value_map")) {
            for (auto& [k, v] : rule_json["source_b_value_map"].items()) {
                mapping.source_b_value_map[k] = v.get<std::string>();
            }
        }
        add_mapping(mapping);
    }
}

std::vector<Anomaly> ConsistencyAnomalyDetector::detect(const UnifiedTimeline& timeline) const {
    std::vector<Anomaly> anomalies;

    for (const auto& mapping : mappings_) {
        // Get events from source A
        auto events_a = timeline.query_by_event_type(mapping.source_a_event_type);
        // Get events from source B
        auto events_b = timeline.query_by_event_type(mapping.source_b_event_type);

        if (events_a.empty() || events_b.empty()) continue;

        // For each event from source A, find matching event from source B
        // within the time window
        for (const auto& event_a : events_a) {
            if (event_a.source_type != mapping.source_a_type) continue;

            // Get value from source A
            auto it_a = event_a.properties.find(mapping.source_a_value_key);
            if (it_a == event_a.properties.end()) continue;

            // Map raw value to semantic value
            std::string semantic_a;
            auto map_it_a = mapping.source_a_value_map.find(it_a->second);
            if (map_it_a != mapping.source_a_value_map.end()) {
                semantic_a = map_it_a->second;
            } else {
                semantic_a = it_a->second;  // Use raw value if no mapping
            }

            // Find closest event from source B within time window
            for (const auto& event_b : events_b) {
                if (event_b.source_type != mapping.source_b_type) continue;

                double time_diff = std::abs(event_a.normalized_timestamp -
                                           event_b.normalized_timestamp);
                if (time_diff > mapping.time_window_s) continue;

                // Get value from source B
                auto it_b = event_b.properties.find(mapping.source_b_value_key);
                if (it_b == event_b.properties.end()) continue;

                // Map raw value to semantic value
                std::string semantic_b;
                auto map_it_b = mapping.source_b_value_map.find(it_b->second);
                if (map_it_b != mapping.source_b_value_map.end()) {
                    semantic_b = map_it_b->second;
                } else {
                    semantic_b = it_b->second;
                }

                // Comparison Mode Switch
                bool is_anomaly = false;

                if (mapping.is_numeric) {
                    try {
                        double val_a = std::stod(semantic_a);
                        double val_b = std::stod(semantic_b);
                        if (std::abs(val_a - val_b) > mapping.numeric_tolerance) {
                            is_anomaly = true;
                        }
                    } catch (...) {
                        // If parsing fails for numeric signal, flag it as anomaly (data corruption)
                        is_anomaly = true;
                    }
                } else {
                    if (semantic_a != semantic_b) {
                        is_anomaly = true;
                    }
                }

                if (is_anomaly) {
                    Anomaly a;
                    a.type = AnomalyType::CONSISTENCY_MISMATCH;
                    a.severity = AnomalySeverity::HIGH;
                    a.timestamp = event_a.normalized_timestamp;
                    a.description = mapping.data_name + " mismatch: " +
                                   mapping.source_a_type + " says '" + semantic_a +
                                   "' but " + mapping.source_b_type + " says '" +
                                   semantic_b + "' (time diff=" +
                                   std::to_string(time_diff) + "s)";
                    a.related_events.push_back(event_a);
                    a.related_events.push_back(event_b);
                    anomalies.push_back(a);
                }
            }
        }
    }

    return anomalies;
}

// ============================================================================
// DLT Error Detector
// ============================================================================
std::vector<Anomaly> DLTErrorDetector::detect(const UnifiedTimeline& timeline) const {
    std::vector<Anomaly> anomalies;

    for (const auto& event : timeline.get_events()) {
        if (event.source_type != "DLT") continue;

        auto level_it = event.properties.find("log_level");
        if (level_it == event.properties.end()) continue;

        if (level_it->second == "error" || level_it->second == "fatal") {
            Anomaly a;
            a.type = AnomalyType::DLT_ERROR;
            a.severity = (level_it->second == "fatal") ?
                         AnomalySeverity::CRITICAL : AnomalySeverity::HIGH;
            a.timestamp = event.normalized_timestamp;
            a.description = "DLT " + level_it->second + " detected: " + event.description;
            a.related_events.push_back(event);
            anomalies.push_back(a);
        }
    }

    return anomalies;
}

} // namespace log_analyzer
