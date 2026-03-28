#pragma once

#include "log_entries.h"
#include <vector>
#include <string>

namespace log_analyzer {

// ============================================================================
// Unified Timeline — merges events from all sources into a single timeline
//
// Addresses Challenge #3: Cross-Source Correlation
// After time synchronization, all events are merged and sorted by timestamp
// to create a unified timeline for cross-source analysis.
//
// Now source-agnostic: accepts generic UnifiedEvent vectors from any parser.
// ============================================================================
class UnifiedTimeline {
public:
    // -- Generic API (used by registry-based engine) --

    /// Add pre-converted events (from ILogParser::parse_to_events)
    void add_events(const std::vector<UnifiedEvent>& events);

    // -- Legacy typed APIs (kept for backward compatibility with tests) --
    void add_can_events(const std::vector<CANLogEntry>& entries);
    void add_dlt_events(const std::vector<DLTLogEntry>& entries);
    void add_mqtt_events(const std::vector<MQTTLogEntry>& entries);
    void add_backend_events(const std::vector<BackendLogEntry>& entries);

    // Build the timeline (sort all events by normalized timestamp)
    void build();

    // Get all events sorted by time
    const std::vector<UnifiedEvent>& get_events() const { return events_; }

    // Query events within a time range [start, end]
    std::vector<UnifiedEvent> query_time_range(double start, double end) const;

    // Query events by source type within a time range
    std::vector<UnifiedEvent> query_by_source(const std::string& source_type,
                                               double start = -1.0,
                                               double end = -1.0) const;

    // Query events by event type within a time range
    std::vector<UnifiedEvent> query_by_event_type(const std::string& event_type,
                                                   double start = -1.0,
                                                   double end = -1.0) const;

    // Get total number of events
    size_t size() const { return events_.size(); }

    // Check if timeline is empty
    bool empty() const { return events_.empty(); }

private:
    std::vector<UnifiedEvent> events_;
    bool is_sorted_ = false;
};

} // namespace log_analyzer
