.PHONY := all clear
.DEAFULT-GOAL: all

SRC := main.c hexconv.c sha1.c
OBJ := $(patsubst %.c,%.o,$(SRC))

CFLAGS := -pedantic -Wall -Werror -Werror

%.o: %.c
	$(CC) -c $(CFLAGS) $^ -o $@

sha1extend: $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

# Utility targets below
all: sha1extend

clear:
	rm -rf $(OBJ) sha1extend
