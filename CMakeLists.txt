cmake_minimum_required(VERSION 4.3)
project(NetSentry)

set(CMAKE_CXX_STANDARD 17)

include_directories(.)

add_executable(NetSentry
        Sniffer.cpp
        Sniffer.h)
