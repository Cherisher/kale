.PHONY: all clean test

CXX := clang++
CXXFLAGS := -Wall -g -std=c++14 -I.. -O2
LDFLAGS := -lpthread -L.. -lkale -lsnappy -lpcap -lnet -lkl
TARGETS := raw_tun_proxy

all: $(TARGETS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

raw_tun_proxy: raw_tun_proxy.o
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)
clean:
	@rm -vf $(TARGETS)
	@rm -vf *.o *.a *.so
