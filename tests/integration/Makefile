#
# Integration tests for the bdshemu self-modifying-code semantics.
#
# These tests link against the static bddisasm/bdshemu libraries. The libraries
# are built with the top-level Makefile if they are missing.
#
# Usage:
#   make test     # build the test binary and run it
#   make          # build the test binary only
#   make clean
#

REPO_ROOT := ../..

LIB_DIR   := $(REPO_ROOT)/bin/x64/Debug
LIBS      := $(LIB_DIR)/libbdshemu.a $(LIB_DIR)/libbddisasm.a
INCLUDES  := -I$(REPO_ROOT)/inc

TARGET    := bdshemu_selfmodifying_test
SRC       := bdshemu_selfmodifying_test.c

CC        ?= cc
CFLAGS    ?= -std=c11 -g -O0 -Wall -Wextra -Wshadow -Werror
LDFLAGS   ?=

.PHONY: all test clean libs

all: $(TARGET)

# Build both configurations of the static libraries, mirroring the top-level
# Makefile; the test links the Debug archives.
libs:
	@$(MAKE) --no-print-directory -C $(REPO_ROOT) bddisasm bdshemu

$(LIBS): libs

$(TARGET): $(SRC) $(LIBS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC) $(LIBS) -o $(TARGET) $(LDFLAGS)

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET)
