cmake_minimum_required(VERSION 4.3)
project(NetSentry)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

include_directories(.)
include_directories(/usr/local/include)

find_package(PcapPlusPlus REQUIRED)
find_package(Qt6 COMPONENTS Core Sql Widgets REQUIRED)
find_package(Threads REQUIRED)

find_library(ONNXRUNTIME_LIB NAMES onnxruntime PATHS /usr/local/lib64 REQUIRED)

#include<moodycamel>

add_executable(NetSentry
        Sniffer.cpp
        Sniffer.h
        Types.cpp
        Types.h)

target_link_libraries(NetSentry PRIVATE
        PcapPlusPlus::Pcap++
        PcapPlusPlus::Packet++
        PcapPlusPlus::Common++
        Qt6::Core
        Qt6::Sql
        Qt6::Widgets
        Threads::Threads
        ${ONNXRUNTIME_LIB}
)