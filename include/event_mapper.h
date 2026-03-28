#pragma once

#include "log_entries.h"
#include "../third_party/nlohmann/json.hpp"
#include <string>
#include <vector>
#include <map>
#include <regex>

namespace log_analyzer {

struct MappingRule {
    std::string source_type;
    std::map<std::string, std::string> filter;
    std::regex payload_regex;
    std::vector<std::string> regex_groups;
    std::string new_event_type;
};

class EventMapper {
public:
    void load_config(const nlohmann::json& config);
    std::vector<UnifiedEvent> map_events(const std::vector<UnifiedEvent>& raw_events) const;

private:
    std::vector<MappingRule> rules_;
};

} // namespace log_analyzer
