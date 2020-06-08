cmake_minimum_required(VERSION 3.16)
project(Sniffer)

set(CMAKE_CXX_STANDARD 14)

add_executable(Sniffer sniffer.cpp protocol.h analyze.cpp analyze.h)
target_link_libraries(Sniffer pcap)
