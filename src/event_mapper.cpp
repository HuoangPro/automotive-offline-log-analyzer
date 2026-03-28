#include "event_mapper.h"
#include <algorithm>
#include <iostream>

using json = nlohmann::json;

namespace log_analyzer {

void EventMapper::load_config(const json& config) {
    if (!config.is_array()) return;
    
    for (const auto& rule_json : config) {
        MappingRule rule;
        rule.source_type = rule_json.value("source_type", "");
        rule.new_event_type = rule_json.value("new_event_type", "");
        
        if (rule_json.contains("filter") && rule_json["filter"].is_object()) {
            for (auto& [k, v] : rule_json["filter"].items()) {
                if (v.is_string()) {
                    rule.filter[k] = v.get<std::string>();
                }
            }
        }
        
        std::string regex_str = rule_json.value("payload_regex", "");
        if (!regex_str.empty()) {
            try {
                rule.payload_regex = std::regex(regex_str);
            } catch (const std::regex_error& e) {
                std::cerr << "EventMapper: Invalid regex pattern '" << regex_str << "': " << e.what() << std::endl;
                continue; // Skip invalid rule
            }
        }
        
        if (rule_json.contains("regex_groups") && rule_json["regex_groups"].is_array()) {
            for (const auto& group : rule_json["regex_groups"]) {
                if (group.is_string()) {
                    rule.regex_groups.push_back(group.get<std::string>());
                }
            }
        }
        
        rules_.push_back(rule);
    }
}

std::vector<UnifiedEvent> EventMapper::map_events(const std::vector<UnifiedEvent>& raw_events) const {
    if (rules_.empty()) return raw_events; // No mapping configured, fast path
    
    std::vector<UnifiedEvent> semantic_events;
    semantic_events.reserve(raw_events.size());
    
    for (const auto& event : raw_events) {
        UnifiedEvent mapped_event = event; // Copy the event
        bool matched = false;
        
        for (const auto& rule : rules_) {
            // Check source_type
            if (!rule.source_type.empty() && event.source_type != rule.source_type) continue;
            
            // Check filters
            bool filter_match = true;
            for (const auto& [filter_key, filter_val] : rule.filter) {
                auto it = event.properties.find(filter_key);
                if (it == event.properties.end() || it->second != filter_val) {
                    filter_match = false;
                    break;
                }
            }
            if (!filter_match) continue;
            
            // Apply regex on payload property if present
            auto payload_it = event.properties.find("payload");
            if (payload_it != event.properties.end() && !rule.regex_groups.empty()) {
                std::smatch match;
                if (std::regex_search(payload_it->second, match, rule.payload_regex)) {
                    // Start from index 1 because match[0] is the whole string
                    for (size_t i = 1; i < match.size() && (i - 1) < rule.regex_groups.size(); ++i) {
                        std::string group_name = rule.regex_groups[i - 1];
                        mapped_event.properties[group_name] = match[i].str();
                        matched = true;
                    }
                } else {
                    continue; // Payload regex didn't match
                }
            } else if (rule.regex_groups.empty()) {
                matched = true; // Rule doesn't require regex matching
            }
            
            // If rule matched
            if (matched) {
                if (!rule.new_event_type.empty()) {
                    mapped_event.event_type = rule.new_event_type;
                }
                // Removed break to allow accumulative matching from multiple rules
            }
        }
        semantic_events.push_back(mapped_event);
    }
    
    return semantic_events;
}

} // namespace log_analyzer
