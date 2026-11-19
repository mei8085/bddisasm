# Functional tests for the bdshemu stack-string tracker.
#
# These tests are self-contained (hand-assembled shellcodes, no external assembler). They link against the
# locally built bddisasm/bdshemu static libraries and the bddisasm CRT stubs.
#
# Usage:
#   make            # build and run the tests
#   make build      # build only

ROOT        := ../..
BDDISASM    := $(ROOT)/bddisasm
BDSHEMU     := $(ROOT)/bdshemu
BIN_LIB_DIR := $(ROOT)/bin/x64/Debug

CC      ?= gcc
CFLAGS  := -std=c11 -D_GNU_SOURCE -D_LIB -DAMD64 -DXEN \
           -DBDDISASM_HAS_VSNPRINTF -DBDDISASM_HAS_MEMSET \
           -I $(ROOT)/inc -I $(BDDISASM)/include -maes -Wall -Wextra

LIBS    := $(BIN_LIB_DIR)/libbdshemu.a $(BIN_LIB_DIR)/libbddisasm.a
SRCS    := test_stack_strings.c $(BDDISASM)/bddisasm_crt.c
OUT     := test_stack_strings

.PHONY: all build libs run clean

all: run

libs:
	$(MAKE) -C $(BDDISASM)
	$(MAKE) -C $(BDSHEMU)

build: libs
	$(CC) $(CFLAGS) $(SRCS) $(LIBS) -o $(OUT)

run: build
	./$(OUT)

clean:
	rm -f $(OUT)
