CC = gcc
CFLAGS  = -Wall -Wextra -O3 -march=native -g -I./source
LDFLAGS = -lssl -lcrypto -lz
ifeq ($(OS),Windows_NT)
    CFLAGS  += -I/mingw64/include
    LDFLAGS += -L/mingw64/lib
endif
TARGETS = encoder decoder
SRCS_ENCODER = source/encoder.c source/suffix_tree.c
OBJS_ENCODER = $(SRCS_ENCODER:.c=.o)
SRCS_DECODER = source/decoder.c
OBJS_DECODER = $(SRCS_DECODER:.c=.o)
DEPS_ENCODER = $(OBJS_ENCODER:.o=.d)
DEPS_DECODER = $(OBJS_DECODER:.o=.d)
all: $(TARGETS)
encoder: $(OBJS_ENCODER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
decoder: $(OBJS_DECODER)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@
clean:
	rm -f $(TARGETS) $(OBJS_ENCODER) $(OBJS_DECODER) $(DEPS_ENCODER) $(DEPS_DECODER)
.PHONY: clean all
-include $(DEPS_ENCODER) $(DEPS_DECODER)
-include $(SRCS_ENCODER:.c=.d) $(SRCS_DECODER:.c=.d)
