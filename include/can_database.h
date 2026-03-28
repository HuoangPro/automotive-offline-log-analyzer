#pragma once

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace log_analyzer {

// ============================================================================
// CAN Signal Definition — mirrors DBC file signal definition
// ============================================================================
struct CANSignalDef {
    std::string name;              // Signal name (e.g., "VehicleSpeed")
    int start_bit = 0;             // Start bit position in the data payload
    int bit_length = 0;            // Number of bits for this signal
    bool is_little_endian = true;  // true=Intel(LE), false=Motorola(BE)
    bool is_signed = false;        // true if signal can be negative
    double factor = 1.0;           // Scaling factor
    double offset = 0.0;           // Offset value
    double min_val = 0.0;          // Minimum physical value
    double max_val = 0.0;          // Maximum physical value
    std::string unit;              // Engineering unit (e.g., "km/h")
};

// ============================================================================
// CAN Message Definition — mirrors DBC file message definition
// ============================================================================
struct CANMessageDef {
    uint32_t id = 0;               // CAN Message ID
    std::string name;              // Message name (e.g., "VehicleStatus")
    int dlc = 8;                   // Expected DLC
    std::vector<CANSignalDef> signals;  // Signals within this message
};

// ============================================================================
// CAN Database — loads from JSON (representing DBC content)
// ============================================================================
class CANDatabase {
public:
    // Load CAN database from JSON file
    bool load(const std::string& filepath);

    // Get message definition by ID, returns nullptr if not found
    const CANMessageDef* get_message(uint32_t id) const;

    // Decode all signals from raw CAN data for a given message ID
    // Returns map of signal_name -> physical_value
    std::map<std::string, double> decode_message(uint32_t id,
                                                  const std::vector<uint8_t>& data) const;

    // Get all loaded message definitions
    const std::map<uint32_t, CANMessageDef>& get_messages() const { return messages_; }

    // Extract raw integer value from CAN data bytes
    // This implements the bit extraction logic based on DBC signal layout
    static uint64_t extract_bits(const std::vector<uint8_t>& data,
                                  int start_bit, int bit_length,
                                  bool is_little_endian);

    // Convert raw value to physical value using factor and offset
    // Formula: physical_value = offset + factor * raw_value
    static double decode_signal(const std::vector<uint8_t>& data,
                                 const CANSignalDef& signal_def);

private:
    std::map<uint32_t, CANMessageDef> messages_;
};

} // namespace log_analyzer
