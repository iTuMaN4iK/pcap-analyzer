cmake_minimum_required(VERSION 3.22)
project(pcap_analyzer)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(3rdparty/CLI11)
add_subdirectory(PcapAnalyzer)

add_executable(pcap_analyzer main.cpp)

target_link_libraries(pcap_analyzer
        PRIVATE
        CLI11::CLI11
        pcap_analyzer_lib)

if (MSVC)
    add_compile_options(/W4)
else ()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif ()