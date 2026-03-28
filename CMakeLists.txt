cmake_minimum_required(VERSION 3.14)
project(log_analyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")

# Find threading library (needed for std::mutex in ParserRegistry)
find_package(Threads REQUIRED)

# Third-party header-only libraries
include_directories(${CMAKE_SOURCE_DIR}/third_party)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Core library
# ============================================================================
add_library(log_analyzer_lib STATIC
    src/log_entries.cpp
    src/can_database.cpp
    src/parsers.cpp
    src/time_synchronizer.cpp
    src/unified_timeline.cpp
    src/anomaly_detectors.cpp
    src/anomaly_report.cpp
    src/analyzer_engine.cpp
    src/event_mapper.cpp
)
target_link_libraries(log_analyzer_lib PUBLIC Threads::Threads)

# ============================================================================
# Main executable
# ============================================================================
add_executable(log_analyzer src/main.cpp)
target_link_libraries(log_analyzer PRIVATE log_analyzer_lib)
