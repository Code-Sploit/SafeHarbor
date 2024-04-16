CC = gcc
CFLAGS = -Wall -Wextra

SRCS = safeharborctl.c
OBJS = $(SRCS:.c=.o)
EXECUTABLE = safeharborctl

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) $(EXECUTABLE)

install:
	cp $(EXECUTABLE) /usr/bin

deinstall:
	rm -f /usr/bin/$(EXECUTABLE)
