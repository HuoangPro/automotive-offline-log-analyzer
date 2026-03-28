#pragma once

#include "log_entries.h"
#include "can_database.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <mutex>

namespace log_analyzer {

// ============================================================================
// ILogParser — Abstract interface for all log parsers
//
// Design rationale:
//   - All parsers output a unified vector<UnifiedEvent>, making the engine
//     source-agnostic. The engine does not need to know which parser types
//     exist — it simply iterates over registered parsers.
//   - Each parser knows its source_type() (e.g. "CAN", "DLT") and
//     file_pattern() (e.g. "can_log.json") for auto-discovery.
//   - Concrete parsers can hold extra context (e.g., CANParser holds
//     a pointer to CANDatabase for signal decoding).
// ============================================================================
class ILogParser {
public:
    virtual ~ILogParser() = default;

    // -- Identity --

    /// Unique source type identifier (e.g. "CAN", "DLT", "MQTT", "BACKEND")
    virtual std::string source_type() const = 0;

    /// Default filename expected in the data directory (e.g. "can_log.json")
    virtual std::string default_filename() const = 0;

    // -- Core parsing --

    /// Parse a log file and return unified events.
    /// The parser is responsible for:
    ///   1. Reading the file
    ///   2. Validating entries (reject invalid ones)
    ///   3. Converting each valid entry into one or more UnifiedEvent objects
    /// Returns an empty vector if the file cannot be opened or parsed.
    virtual std::vector<UnifiedEvent> parse_to_events(const std::string& filepath) const = 0;
};

// ============================================================================
// ParserRegistry — Registry Pattern for log parsers
//
// Allows third-party modules to register new log parsers at runtime
// without modifying the engine or existing parser code.
//
// Usage (by parser developer):
//   // In parser .cpp file — automatic registration via static initializer:
//   static bool registered = ParserRegistry::instance().register_parser(
//       "MY_SOURCE", [](){ return std::make_unique<MySourceParser>(); }
//   );
//
// Usage (by engine):
//   auto& registry = ParserRegistry::instance();
//   for (const auto& source_type : registry.registered_types()) {
//       auto parser = registry.get(source_type);
//       auto events = parser->parse_to_events(filepath);
//   }
// ============================================================================
class ParserRegistry {
public:
    /// Factory function type: creates a new parser instance
    using FactoryFn = std::function<std::unique_ptr<ILogParser>()>;

    /// Get the singleton instance
    static ParserRegistry& instance();

    /// Register a parser factory under a source type key.
    /// Returns true if registration succeeded, false if key already exists.
    bool register_parser(const std::string& source_type, FactoryFn factory);

    /// Get the singleton parser instance for the given source type.
    /// Returns nullptr if the source type is not registered.
    std::shared_ptr<ILogParser> get(const std::string& source_type) const;

    /// Check if a source type is registered
    bool has(const std::string& source_type) const;

    /// Get all registered source type names
    std::vector<std::string> registered_types() const;

    /// Get all registered parser instances
    std::vector<std::shared_ptr<ILogParser>> get_all() const;

    /// Unregister a parser (useful for testing)
    void unregister_parser(const std::string& source_type);

    /// Clear all registrations (useful for testing)
    void clear();

private:
    ParserRegistry() = default;
    ParserRegistry(const ParserRegistry&) = delete;
    ParserRegistry& operator=(const ParserRegistry&) = delete;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<ILogParser>> instances_;
};

// ============================================================================
// Helper macro for auto-registration
// Place in the header file right after the class definition.
// Example:
//   REGISTER_PARSER(CANParser, "CAN")
// ============================================================================
#define REGISTER_PARSER(ParserClass, SourceType) \
    inline bool _registered_##ParserClass = \
        log_analyzer::ParserRegistry::instance().register_parser( \
            SourceType, \
            [](){ return std::make_unique<ParserClass>(); } \
        )

// ============================================================================
// Concrete Parsers — inherit from ILogParser
// ============================================================================

// -- CAN Parser ---------------------------------------------------------------
class CANParser : public ILogParser {
public:
    explicit CANParser(const CANDatabase* can_db = nullptr);

    std::string source_type() const override { return "CAN"; }
    std::string default_filename() const override { return "can_log.json"; }

    std::vector<UnifiedEvent> parse_to_events(const std::string& filepath) const override;

    // Set CAN database for signal decoding (post-construction injection)
    void set_can_database(const CANDatabase* can_db) { can_db_ = can_db; }

    // -- Legacy typed API (kept for backward compatibility & quality assessor) --
    std::vector<CANLogEntry> parse(const std::string& filepath) const;
    static bool validate(const CANLogEntry& entry);

private:
    const CANDatabase* can_db_ = nullptr;

    // Convert a parsed CANLogEntry into UnifiedEvent(s)
    std::vector<UnifiedEvent> to_events(const CANLogEntry& entry) const;
};
REGISTER_PARSER(CANParser, "CAN");

// -- DLT Parser ---------------------------------------------------------------
class DLTParser : public ILogParser {
public:
    std::string source_type() const override { return "DLT"; }
    std::string default_filename() const override { return "dlt_log.json"; }

    std::vector<UnifiedEvent> parse_to_events(const std::string& filepath) const override;

    // -- Legacy typed API --
    std::vector<DLTLogEntry> parse(const std::string& filepath) const;
    static bool validate(const DLTLogEntry& entry);

private:
    std::vector<UnifiedEvent> to_events(const DLTLogEntry& entry) const;
};
REGISTER_PARSER(DLTParser, "DLT");

// -- MQTT Parser --------------------------------------------------------------
class MQTTParser : public ILogParser {
public:
    std::string source_type() const override { return "MQTT"; }
    std::string default_filename() const override { return "mqtt_log.json"; }

    std::vector<UnifiedEvent> parse_to_events(const std::string& filepath) const override;

    // -- Legacy typed API --
    std::vector<MQTTLogEntry> parse(const std::string& filepath) const;
    static bool validate(const MQTTLogEntry& entry);

private:
    std::vector<UnifiedEvent> to_events(const MQTTLogEntry& entry) const;
};
REGISTER_PARSER(MQTTParser, "MQTT");

// -- Backend Parser -----------------------------------------------------------
class BackendParser : public ILogParser {
public:
    std::string source_type() const override { return "BACKEND"; }
    std::string default_filename() const override { return "backend_log.json"; }

    std::vector<UnifiedEvent> parse_to_events(const std::string& filepath) const override;

    // -- Legacy typed API --
    std::vector<BackendLogEntry> parse(const std::string& filepath) const;
    static bool validate(const BackendLogEntry& entry);

private:
    std::vector<UnifiedEvent> to_events(const BackendLogEntry& entry) const;
};
REGISTER_PARSER(BackendParser, "BACKEND");

} // namespace log_analyzer
