CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror

TARGET = test_storage_browser_messages
SOURCES = test_storage_browser_messages.c \
	../main/pages/shared/storage_browser_messages.c

all: $(TARGET)

$(TARGET): $(SOURCES) ../main/pages/shared/storage_browser_messages.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES)

run: $(TARGET)
	./$(TARGET)
	python3 test_ui_regressions.py

clean:
	rm -f $(TARGET)

.PHONY: all run clean
