CC = cc
CFLAGS = -Wall -Wextra -std=c11 -g

.PHONY: all clean

all: simulator

simulator: simulator.c
	$(CC) $(CFLAGS) -o simulator simulator.c

clean:
	rm -f simulator
