CC = gcc
CFLAGS  += -I/mingw64/include
LDFLAGS += -L/mingw64/lib -lssl -lcrypto

CFLAGS = -Wall -g -I./source

LDFLAGS = -lssl -lcrypto

# --- Targets ---

TARGETS = encoder decoder

# --- Sources and Objetcts ---

SRCS_ENCODER = source/encoder.c source/suffix_tree.c
OBJS_ENCODER = $(SRCS_ENCODER:.c=.o)

SRCS_DECODER = source/decoder.c
OBJS_DECODER = $(SRCS_DECODER:.c=.o)

# --- Rules ---

all: $(TARGETS)

encoder: $(OBJS_ENCODER)
	@echo "Linking the executable$@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

decoder: $(OBJS_DECODER)
	@echo "Linking the executable...$@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	@echo "Compiling..."
	$(CC) $(CFLAGS) -c $< -o $@ -MMD

.PHONY: clean all

clean:
	@echo "Cleaning the generated files..."
	rm -f $(TARGETS) $(OBJS_ENCODER) $(OBJS_DECODER) $(SRCS_ENCODER:.c=.d) $(SRCS_DECODER:.c=.d)

-include $(SRCS_ENCODER:.c=.d) $(SRCS_DECODER:.c=.d)
