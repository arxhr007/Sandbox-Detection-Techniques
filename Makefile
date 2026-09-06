# Build the sandbox detector (Windows / MinGW-w64) and run the pure-logic tests.
#
# Requires MinGW-w64 gcc for the Windows binary (uses Vista+ Win32 APIs, so the
# legacy MinGW.org toolchain will not build it). The test target only needs a
# stock C compiler -- it links the Win32-free scoring core.
#
#   make            # build sandbox_detector.exe
#   make run        # build then run it
#   make test       # build + run the unit tests (portable)
#   make clean      # remove build outputs

# Default to gcc, but honour an explicit CC from the environment or command line.
# (make predefines CC=cc, so a plain ?= would not take effect.)
ifeq ($(origin CC),default)
CC := gcc
endif
CFLAGS   ?= -Wall -Wextra -O2
INCLUDES := -Isrc
LDLIBS   := -lws2_32 -liphlpapi

TARGET   := sandbox_detector.exe
SRC      := src/detector.c src/checks.c src/main.c

TEST_BIN := test_detector.exe
TEST_SRC := src/detector.c tests/test_detector.c

.PHONY: all run test clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TARGET) $(SRC) $(LDLIBS)

run: $(TARGET)
	./$(TARGET)

test: $(TEST_SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(TEST_BIN) $(TEST_SRC)
	./$(TEST_BIN)

clean:
	rm -f $(TARGET) $(TEST_BIN)
