
CXXFLAGS += -g2

bin/bootit: boot-it.cc bootpd.cc tftpd.cc cfgparser.h
	mkdir -p bin
	g++ $(CXXFLAGS) -o $@ $^

all: bin/bootit

clean:
	rm -rf bin

.PHONY: all clean