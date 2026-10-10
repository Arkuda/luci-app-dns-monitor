CC ?= cc
CFLAGS ?= -O2
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lubus -lubox -ljson-c -lm

.PHONY: all compile install clean
all: dns-monitor
compile: dns-monitor

dns-monitor: dns-monitor.o collector.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c collector.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra -c -o $@ $<

install: dns-monitor
	install -d $(DESTDIR)/usr/sbin
	install -m 0755 dns-monitor $(DESTDIR)/usr/sbin/dns-monitor

clean:
	rm -f dns-monitor dns-monitor.o collector.o
