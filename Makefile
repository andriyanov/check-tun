override CFLAGS += -I keepalived
override CFLAGS += -std=gnu99 -D_GNU_SOURCE
override LDLIBS += -lnetfilter_queue -lpthread

OBJECTS += check-tun.o
OBJECTS += nfq.o
OBJECTS += config.o
OBJECTS += keepalived/parser.o
OBJECTS += keepalived/utils.o
OBJECTS += keepalived/logger.o
OBJECTS += keepalived/memory.o
OBJECTS += keepalived/vector.o

check-tun: $(OBJECTS)

install: check-tun
	install -d ${DESTDIR}/usr/sbin
	install check-tun ${DESTDIR}/usr/sbin

clean:
	rm $(OBJECTS) check-tun 2>/dev/null || true

.PHONY: clean
