#include "log_entries.h"

namespace log_analyzer {

std::string Anomaly::type_to_string() const {
    switch (type) {
        case AnomalyType::SIGNAL_RANGE:         return "SIGNAL_RANGE";
        case AnomalyType::SIGNAL_SPIKE:         return "SIGNAL_SPIKE";
        case AnomalyType::SIGNAL_FREEZE:        return "SIGNAL_FREEZE";
        case AnomalyType::SEQUENCE_VIOLATION:   return "SEQUENCE_VIOLATION";
        case AnomalyType::TIMING_MESSAGE_LOSS:  return "TIMING_MESSAGE_LOSS";
        case AnomalyType::TIMING_JITTER:        return "TIMING_JITTER";
        case AnomalyType::CONSISTENCY_MISMATCH: return "CONSISTENCY_MISMATCH";
        case AnomalyType::DLT_ERROR:            return "DLT_ERROR";
        default: return "UNKNOWN";
    }
}

std::string Anomaly::severity_to_string() const {
    switch (severity) {
        case AnomalySeverity::LOW:      return "LOW";
        case AnomalySeverity::MEDIUM:   return "MEDIUM";
        case AnomalySeverity::HIGH:     return "HIGH";
        case AnomalySeverity::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}


} // namespace log_analyzer
