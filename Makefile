# flags
LIBS?=
LIBS+=-lc

CPPFLAGS?=
CPPFLAGS+=-Wall -Wextra -MD -Iinclude -std=c99

LDFLAGS?=
LDFLAGS+=$(LIBS)

# programs
CC=gcc
LD=ld

# files
SRC=src/main.c \
src/hashmap.c\
src/algo_utils.c \
src/caesar.c \
src/viginere.c \
src/rsa.c
SRC_MAKE=$(SRC:.c=.d)
OBJ=$(SRC:.c=.o)
BIN=encro

all: $(BIN)

%.o: %.c
	@echo "CC $@"
	@$(CC) -o $@ -c $< $(CPPFLAGS) $(CFLAGS)

clean:
	rm -f $(OBJ) $(SRC_MAKE) $(BIN)

$(BIN): $(OBJ)
	@$(CC) -o $@ $(LDFLAGS) $(OBJ)

-include $(SRC_MAKE)

.PHONY: all clean
