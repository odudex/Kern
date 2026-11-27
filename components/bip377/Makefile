CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LDFLAGS =
INCLUDES = -Iinclude -Isrc

# DEBUG=1 builds with ASan + UBSan; run `make clean` when toggling. WERROR=1
# turns warnings into errors, as CI does.
ifeq ($(DEBUG),1)
  CFLAGS += -O0 -fno-omit-frame-pointer -fsanitize=address,undefined
  LDFLAGS += -fsanitize=address,undefined
else
  CFLAGS += -O2
endif
ifeq ($(WERROR),1)
  CFLAGS += -Werror
endif

SOURCES = src/bip377_common.c src/bip377_decode.c src/bip377_encode.c
OBJECTS = $(SOURCES:.c=.o)
LIB = src/libbip377.a

TESTS = test/test_vectors test/test_api
VECTORS = $(wildcard test/vectors/*.json)

all: $(LIB) $(TESTS)

$(LIB): $(OBJECTS)
	ar rcs $@ $^

src/%.o: src/%.c include/bip377.h src/bip377_internal.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

test/%: test/%.c test/vectors.h include/bip377.h $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LIB) $(LDFLAGS)

# The tests read the vectors relative to this directory
run: $(TESTS) $(VECTORS)
	./test/test_vectors
	./test/test_api

# Compile-only portability check; requires GCC's 32-bit development headers.
check32:
	$(CC) $(CFLAGS) $(INCLUDES) -m32 -Werror=type-limits -fsyntax-only $(SOURCES)

clean:
	rm -f $(OBJECTS) $(LIB) $(TESTS)

.PHONY: all run check32 clean
