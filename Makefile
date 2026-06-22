# Makefile for Packet Sniffer - Redes I
# Requires: MinGW-w64 (g++) and Npcap SDK
#
# Default Npcap SDK path - change if installed elsewhere
NPCAP_SDK ?= C:/Program Files/Npcap/sdk

CXX      = g++
CXXFLAGS = -std=c++11 -Wall -O2 \
           -I include \
           -I "$(NPCAP_SDK)/Include"

LDFLAGS  = -L "$(NPCAP_SDK)/Lib/x64" \
           -lwpcap -lws2_32 -lIPHlpApi

TARGET   = sniffer.exe

SRCS = src/main.cpp \
       src/capture.cpp \
       src/ui.cpp \
       src/export.cpp \
       src/device.cpp

OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp include/sniffer.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	del /Q src\*.o $(TARGET) 2>nul || true

.PHONY: all clean
