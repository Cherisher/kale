.PHONY: all clean test

KL := kl
KL_LIB := $(KL)/libkl.a
SNAPPY := snappy
SNAPPY_LIB := libsnappy.a
LIBPCAP := libpcap
LIBPCAP_LIB := libpcap.a
CXX := clang++
CXXFLAGS := -Wall -g -std=c++14 -I$(LIBPCAP)
LDFLAGS := -lpthread -L. -lkale -lsnappy -lpcap -L$(KL) -lkl
STATICLIB := libkale.a
OBJECTS := tun.o pcap++.o
TESTS := $(patsubst %.cc, %, $(wildcard *_test.cc))

all: $(STATICLIB) $(TESTS)

$(SNAPPY_LIB): $(SNAPPY)
	@cd $< && ./autogen.sh && ./configure && $(MAKE) && cp .libs/libsnappy.a ../

$(LIBPCAP_LIB): $(LIBPCAP)
	@cd $< && ./configure && $(MAKE) && cp $@ ../

$(SNAPPY):
	@git submodule update --remote $@

$(LIBPCAP):
	@git submodule update --remote $@

$(KL_LIB): $(KL)
	$(MAKE) -C $< all

$(KL):
	@git submodule update --remote $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(STATICLIB): $(OBJECTS)
	@ar rcsv $@ $^

$(TESTS): $(STATICLIB) $(KL_LIB) $(SNAPPY_LIB) $(LIBPCAP_LIB)

$(TESTS): %_test: %_test.o
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

test: $(TESTS)
	@for test in $^; do ./$$test || exit 1; done
	@echo "==== CONG! ALL TESTS PASSED."

clean:
	@rm -rvf *.o *.a *.so $(TESTS)
