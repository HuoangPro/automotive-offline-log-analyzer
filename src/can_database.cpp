#include "can_database.h"
#include "../third_party/nlohmann/json.hpp"
#include <fstream>
#include <stdexcept>
#include <cmath>

using json = nlohmann::json;

namespace log_analyzer {

bool CANDatabase::load(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    try {
        json j;
        file >> j;

        if (!j.contains("messages") || !j["messages"].is_array()) {
            return false;
        }

        for (const auto& msg_json : j["messages"]) {
            CANMessageDef msg;
            msg.id = msg_json.value("id", 0u);
            msg.name = msg_json.value("name", "");
            msg.dlc = msg_json.value("dlc", 8);

            if (msg_json.contains("signals") && msg_json["signals"].is_array()) {
                for (const auto& sig_json : msg_json["signals"]) {
                    CANSignalDef sig;
                    sig.name = sig_json.value("name", "");
                    sig.start_bit = sig_json.value("start_bit", 0);
                    sig.bit_length = sig_json.value("bit_length", 0);
                    sig.is_little_endian = sig_json.value("is_little_endian", true);
                    sig.is_signed = sig_json.value("is_signed", false);
                    sig.factor = sig_json.value("factor", 1.0);
                    sig.offset = sig_json.value("offset", 0.0);
                    sig.min_val = sig_json.value("min_val", 0.0);
                    sig.max_val = sig_json.value("max_val", 0.0);
                    sig.unit = sig_json.value("unit", "");
                    msg.signals.push_back(sig);
                }
            }

            messages_[msg.id] = msg;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

const CANMessageDef* CANDatabase::get_message(uint32_t id) const {
    auto it = messages_.find(id);
    if (it != messages_.end()) {
        return &it->second;
    }
    return nullptr;
}

uint64_t CANDatabase::extract_bits(const std::vector<uint8_t>& data,
                                    int start_bit, int bit_length,
                                    bool is_little_endian) {
    uint64_t result = 0;

    if (is_little_endian) {
        // Intel byte order (Little Endian):
        // Bit numbering: byte0[0..7], byte1[8..15], byte2[16..23], ...
        // Bits are laid out continuously from start_bit
        for (int i = 0; i < bit_length; i++) {
            int bit_pos = start_bit + i;
            int byte_idx = bit_pos / 8;
            int bit_idx = bit_pos % 8;
            if (byte_idx < static_cast<int>(data.size())) {
                uint64_t bit_val = (data[byte_idx] >> bit_idx) & 1u;
                result |= (bit_val << i);
            }
        }
    } else {
        // Motorola byte order (Big Endian):
        // DBC Motorola bit numbering:
        //   Byte 0: bits 7  6  5  4  3  2  1  0
        //   Byte 1: bits 15 14 13 12 11 10 9  8
        //   ...
        // start_bit is the MSB position in this numbering
        // We read bit_length bits starting from MSB downward
        int bit_pos = start_bit;
        for (int i = 0; i < bit_length; i++) {
            int byte_idx = bit_pos / 8;
            int bit_in_byte = bit_pos % 8;
            if (byte_idx < static_cast<int>(data.size())) {
                uint64_t bit_val = (data[byte_idx] >> bit_in_byte) & 1u;
                result = (result << 1) | bit_val;
            }

            // Move to next bit in Motorola layout
            if (bit_in_byte == 0) {
                // Jump to next byte, bit 7
                bit_pos += 15;  // e.g., from bit 0 (byte0) to bit 15 (byte1 bit7)
            } else {
                bit_pos--;
            }
        }
    }

    return result;
}

double CANDatabase::decode_signal(const std::vector<uint8_t>& data,
                                   const CANSignalDef& signal_def) {
    uint64_t raw = extract_bits(data, signal_def.start_bit, signal_def.bit_length,
                                 signal_def.is_little_endian);

    double raw_value;
    if (signal_def.is_signed) {
        // Sign extension for signed values
        uint64_t sign_bit = 1ULL << (signal_def.bit_length - 1);
        if (raw & sign_bit) {
            // Negative value: extend sign
            uint64_t mask = ~((1ULL << signal_def.bit_length) - 1);
            raw |= mask;
        }
        raw_value = static_cast<double>(static_cast<int64_t>(raw));
    } else {
        raw_value = static_cast<double>(raw);
    }

    // Formula: physical_value = offset + factor * raw_value
    return signal_def.offset + signal_def.factor * raw_value;
}

std::map<std::string, double> CANDatabase::decode_message(
    uint32_t id, const std::vector<uint8_t>& data) const {

    std::map<std::string, double> result;
    const CANMessageDef* msg = get_message(id);
    if (!msg) {
        return result;
    }

    for (const auto& sig : msg->signals) {
        result[sig.name] = decode_signal(data, sig);
    }

    return result;
}

} // namespace log_analyzer
