.PHONY: all clean test

KL := kl
KL_LIB := $(KL)/libkl.a
SNAPPY := snappy
SNAPPY_LIB := libsnappy.a
CXX := clang++
CXXFLAGS := -Wall -g -std=c++14
LDFLAGS := -lpthread -L. -lkale -lsnappy -L$(KL) -lkl
STATICLIB := libkale.a
OBJECTS := tun.o lo_tun.o
TESTS := $(patsubst %.cc, %, $(wildcard *_test.cc))

all: $(STATICLIB) $(TESTS)

$(SNAPPY_LIB): $(SNAPPY)
	@cd $< && ./autogen.sh && ./configure && $(MAKE) && cp .libs/libsnappy.a ../

$(SNAPPY):
	@git submodule update --remote $@

$(KL_LIB): $(KL)
	$(MAKE) -C $< all

$(KL):
	@git submodule update --remote $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(STATICLIB): $(OBJECTS)
	@ar rcsv $@ $^

$(TESTS): $(STATICLIB) $(KL_LIB) $(SNAPPY_LIB)

$(TESTS): %_test: %_test.o
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

test: $(TESTS)
	@for test in $^; do ./$$test || exit 1; done
	@echo "==== CONG! ALL TESTS PASSED."

clean:
	@rm -rvf *.o *.a *.so $(TESTS)
