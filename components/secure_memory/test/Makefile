CC ?= cc
CFLAGS = -O2 -g -Wall -Wextra -Werror
ROOT = ../../..
SOURCES = test_cleanup.c ../secure_memory.c $(ROOT)/main/utils/session_cleanup.c

.PHONY: run clean
run: test_cleanup test_secret_alloc
	./test_cleanup
	./test_secret_alloc

test_secret_alloc: test_secret_alloc.c ../secret_alloc.c ../include/secure_memory.h esp_heap_caps.h
	$(CC) $(CFLAGS) -DSECRET_ALLOC_TEST -I. -I../include test_secret_alloc.c ../secret_alloc.c -o $@

test_cleanup: $(SOURCES) ../include/secure_memory.h multi_heap.h $(ROOT)/main/utils/session_cleanup.h
	$(CC) $(CFLAGS) -DSECURE_HEAP_TEST -I. -I../include -I$(ROOT)/main/utils $(SOURCES) -o $@

clean:
	rm -f test_cleanup test_secret_alloc
