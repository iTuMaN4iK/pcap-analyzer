cmake_minimum_required(VERSION 3.28)
project(pcap_analyzer_lib)

set(CMAKE_CXX_STANDARD 17)

add_library(pcap_analyzer_lib
        STATIC
        src/PcapAnalyzer.cpp
        src/AnalyzeResult.cpp
        src/AnalyzeResultWriter.cpp
)

find_library(PCAP_LIB pcap)
target_link_libraries(pcap_analyzer_lib
        PRIVATE
        ${PCAP_LIB})

if (NOT PCAP_LIB)
    message(FATAL_ERROR "PCAP not found!")
endif ()

target_include_directories(pcap_analyzer_lib
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

