CFLAGS += -I keepalived
CFLAGS += -D_GNU_SOURCE -Dmemcpy=memmove
LDLIBS += -lnetfilter_queue

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
