# Build the sandbox detector (Windows / MinGW-w64).
#
# Requires MinGW-w64 gcc (native or cross-compile). The program uses the Win32
# API (winsock2, iphlpapi, tlhelp32, shell, registry) and does not build on Linux
# without a mingw cross toolchain.
#
#   make            # build sandbox_detector.exe
#   make run        # build then run it
#   make clean      # remove the binary

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDLIBS  := -lws2_32 -liphlpapi
TARGET  := sandbox_detector.exe
SRC     := sandbox_detector.c

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
