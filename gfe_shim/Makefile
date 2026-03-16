ifeq ($(origin CC),default)
CC := x86_64-w64-mingw32-gcc
endif
CFLAGS ?= -O2 -Wall -Wextra -s
LDFLAGS ?=
OUT_DIR := build
OUT_DLL := $(OUT_DIR)/GfeSDK.dll
SRC := GfeSDK.c
DEF := GfeSDK.def

.PHONY: all clean

all: $(OUT_DLL)

$(OUT_DLL): $(SRC) $(DEF)
	mkdir -p $(OUT_DIR)
	$(CC) $(CFLAGS) -shared -o $(OUT_DLL) $(SRC) $(DEF) -lws2_32 $(LDFLAGS)

clean:
	rm -rf $(OUT_DIR)
