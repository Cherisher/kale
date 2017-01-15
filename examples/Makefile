.PHONY: all clean test

LIBPCAP := ../libpcap
CXX := g++
CXXFLAGS := -Wall -g -std=c++14 -I.. -I$(LIBPCAP) -O2
LDFLAGS := -lpthread -L.. -lkale -lsnappy -lpcap -lkl
OBJECTS := raw_tun_proxy.o tun_proxy_remote.o baidu_test.o \
	google_test.o dns_query.o

TARGETS := $(patsubst %.o, %, $(OBJECTS))

all: $(TARGETS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -fPIC -c $<

$(TARGETS): %: %.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@rm -vf $(TARGETS)
	@rm -vf *.o *.a *.so
