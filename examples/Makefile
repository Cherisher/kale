.PHONY: all clean test

LIBPCAP := ../libpcap
CXX := clang++
CXXFLAGS := -Wall -g -std=c++14 -I.. -I$(LIBPCAP) -O2
LDFLAGS := -lpthread -L.. -lkale -lsnappy -lpcap -lnet -lkl
OBJECTS := raw_tun_proxy.o raw_tun_proxy_remote.o
TARGETS := $(patsubst %.o, %, $(OBJECTS))

all: $(TARGETS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(TARGETS): %: %.o
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

clean:
	@rm -vf $(TARGETS)
	@rm -vf *.o *.a *.so
