CC?=     cc
CFLAGS+= -Wall -fsanitize=address -fstack-protector -g -fno-omit-frame-pointer -g3
LIBS+=   -lpthread
TARGET=  test-privsep
OBJS=    test.o privsep_common.o privsep_sandbox.o privsep_dispatch.o privsep_sandbox_linux.o privsep_sandbox_freebsd.o

all:    $(TARGET)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

clean:
	rm -fr $(OBJS) $(TARGET)

.PHONY: clean
