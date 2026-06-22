cmake_minimum_required(VERSION 3.10)
project(packet_sniffer)

set(CMAKE_CXX_STANDARD 11)


set(NPCAP_SDK "C:/Uni/redes/npcap-sdk-1.13")

include_directories(
    include
    ${NPCAP_SDK}/Include
)

link_directories(
    ${NPCAP_SDK}/Lib/x64
)

add_executable(sniffer
    src/main.cpp
    src/capture.cpp
    src/ui.cpp
    src/export.cpp
    src/device.cpp
)

target_link_libraries(sniffer
    wpcap
    ws2_32
    IPHlpApi
)
