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
set(CMAKE_AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/GUI")

add_executable(NetSentry
        Sources/Sniffer.cpp
        Headers/Sniffer.h
        Sources/Types.cpp
        Headers/Types.h
        Sources/FlowManager.cpp
        Headers/FlowManager.h
        Sources/FeatureExtractor.cpp
        Headers/FeatureExtractor.h
        Sources/Engine.cpp
        Headers/Engine.h
        Headers/DB.h
        Sources/DB.cpp
        Headers/HomePage.h
        Sources/HomePage.cpp
        Headers/LiveCapturePage.h
        Sources/LiveCapturePage.cpp
        Headers/FileCapturePage.h
        Sources/FileCapturePage.cpp
        Headers/AlertPage.h
        Sources/AlertPage.cpp
        Headers/MainWindow.h
        Sources/MainWindow.cpp
        main.cpp
)

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