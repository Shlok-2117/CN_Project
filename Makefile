# Makefile - Member 2 local unit test only.
#
# This is NOT one of the four submission Makefiles (those are Member 6's job and
# must build exactly "server" and "client"). This one only builds and runs the
# protocol layer's standalone test.
#
#   make        - build the test binary
#   make test   - build and run it
#   make asan   - build and run under AddressSanitizer + UBSan
#   make clean  - remove binaries

CXX      := g++
CXXFLAGS := -O2 -Wall -Wextra -pthread -std=c++17

all: test_protocol

test_protocol: test_protocol.cpp protocol.cpp protocol.h common_types.h
	$(CXX) $(CXXFLAGS) test_protocol.cpp protocol.cpp -o test_protocol

test: test_protocol
	./test_protocol

asan: test_protocol.cpp protocol.cpp protocol.h common_types.h
	$(CXX) -g -O1 -Wall -Wextra -pthread -std=c++17 \
	       -fsanitize=address,undefined -fno-omit-frame-pointer \
	       test_protocol.cpp protocol.cpp -o test_protocol_asan
	./test_protocol_asan

clean:
	rm -f test_protocol test_protocol_asan *.o

.PHONY: all test asan clean
