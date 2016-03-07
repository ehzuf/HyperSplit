#
#     Filename: Makefile
#  Description: Standalone makefile for packet classification evaluation
#
#       Author: Xiang Wang (xiang.wang.s@gmail.com)
#               Chang Chen (ck-cc@hotmail.com)
#
# Organization: Network Security Laboratory (NSLab),
#               Research Institute of Information Technology (RIIT),
#               Tsinghua University (THU)
#
CODE_DIR = code
BUILD_DIR = build

SRC = $(wildcard $(CODE_DIR)/*.c)
DEP = $(patsubst $(CODE_DIR)/%.c, $(BUILD_DIR)/%.d, $(SRC))
OBJ = $(patsubst $(CODE_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRC))
BIN = $(BUILD_DIR)/pc_algo

CC = gcc
CFLAGS = -Wall -g -O2

all: $(BIN)

ifneq "$(MAKECMDGOALS)" "clean"
    -include $(DEP)
endif

$(BUILD_DIR)/%.o: $(CODE_DIR)/%.c
	$(CC) -c -o $@ $(CFLAGS) $<

$(BUILD_DIR)/%.d: $(CODE_DIR)/%.c
	@set -e; rm -f $@; \
	$(CC) -M -MT $(patsubst %.d, %.o, $@) $(CFLAGS) $< > $@.$$$$; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@.$$$$ > $@; \
	rm -f $@.$$$$

$(BIN): $(OBJ)
	$(CC) -o $@ $^

clean:
	rm -f $(BUILD_DIR)/*

