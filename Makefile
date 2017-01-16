.PHONY: all clean test

KL := kl
KL_LIB := libkl.a
SNAPPY := snappy
SNAPPY_LIB := libsnappy.a
ZSTD := zstd
ZSTD_LIB := libzstd.a
LIBPCAP := libpcap
LIBPCAP_LIB := libpcap.a
CXX := g++
CXXFLAGS := -Wall -g -std=c++14 -I$(LIBPCAP) -I$(ZSTD)/lib -O2
LDFLAGS := -lpthread -L. -lkale -lsnappy -lpcap -lkl -lzstd
STATICLIB := libkale.a
OBJECTS := tun.o ip_packet.o sniffer.o resolver.o arcfour.o demo_coding.o
TESTS := $(patsubst %.cc, %, $(wildcard *_test.cc))

all: $(STATICLIB) $(TESTS)

$(ZSTD_LIB): $(ZSTD)
	@cd $< && $(MAKE) && cp ./lib/libzstd.a ..

$(SNAPPY_LIB): $(SNAPPY)
	@cd $< && ./autogen.sh && ./configure && $(MAKE) && cp .libs/libsnappy.a ../

$(LIBPCAP_LIB): $(LIBPCAP)
	@cd $< && ./configure && $(MAKE) && cp $@ ../

$(SNAPPY):
	@git submodule update --remote $@

$(LIBPCAP):
	@git submodule update --remote $@

$(KL_LIB): $(KL)
	@cd $< && $(MAKE) all && cp libkl.a ../

$(KL):
	@git submodule update --remote $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(STATICLIB): $(OBJECTS)
	@ar rcsv $@ $^

$(TESTS): $(STATICLIB) $(KL_LIB) $(SNAPPY_LIB) $(LIBPCAP_LIB) $(ZSTD_LIB)

$(TESTS): %_test: %_test.o
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

test: $(TESTS)
	@for test in $^; do ./$$test || exit 1; done
	@echo "==== CONG! ALL TESTS PASSED."

clean:
	@rm -rvf *.o *.a *.so $(TESTS)
