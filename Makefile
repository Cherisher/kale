.PHONY: all clean test

KL := kl
KL_LIB := $(KL)/libkl.a
CXX := clang++
CXXFLAGS := -Wall -g -std=c++14 -O2
LDFLAGS := -L. -lkale -L$(KL) -lkl
STATICLIB := libkale.a
OBJECTS := tun.o
TESTS := $(patsubst %.cc, %, $(wildcard *_test.cc))

all: $(STATICLIB) $(TESTS)

$(KL_LIB): $(KL)
	$(MAKE) -C $< all

$(KL):
	git submodule update --remote $@

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
