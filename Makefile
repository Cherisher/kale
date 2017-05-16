.PHONY: all clean test

KL := kl
KL_LIB := libkl.a
CXX := g++
CXXFLAGS := -Wall -g -std=c++14 -O2
LDFLAGS := -lpthread -L. -lkale -lpcap -lkl -ldbus-1
STATICLIB := libkale.a
OBJECTS := tun.o ip_packet.o sniffer.o resolver.o arcfour.o demo_coding.o
TESTS := $(patsubst %.cc, %, $(wildcard *_test.cc))

all: $(STATICLIB) $(TESTS)

$(KL_LIB): $(KL)
	@cd $< && $(MAKE) all && cp libkl.a ../

$(KL):
	@git submodule update --remote $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(STATICLIB): $(OBJECTS)
	@ar rcsv $@ $^

$(TESTS): $(STATICLIB) $(KL_LIB)

$(TESTS): %_test: %_test.o
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

test: $(TESTS)
	@for test in $^; do ./$$test || exit 1; done
	@echo "==== CONG! ALL TESTS PASSED."

clean:
	@rm -rvf *.o *.a *.so $(TESTS)
