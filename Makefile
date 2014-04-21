CFLAGS += -I keepalived
LDFLAGS += -lnetfilter_queue

OBJECTS += check-tun.o
OBJECTS += nfq.o
OBJECTS += config.o
OBJECTS += keepalived/parser.o
OBJECTS += keepalived/utils.o
OBJECTS += keepalived/logger.o
OBJECTS += keepalived/memory.o
OBJECTS += keepalived/vector.o

check-tun: $(OBJECTS)

clean:
	rm $(OBJECTS) check-tun 2>/dev/null || true