# Build the netinspect LD_PRELOAD redirector.
#
#   make            -> builds libnetinspect.so (default)
#   make clean      -> removes the build artifact
#
# The Go side embeds modes/preload/libnetinspect.so via go:embed,
# so the output file name must stay exactly libnetinspect.so.
# lib.c lives in src/ because a Go package dir may not contain .c files.

CC      ?= gcc
CFLAGS  ?= -O2 -fPIC -Wall -Wextra
LDFLAGS := -shared
LDLIBS  := -ldl -pthread

all: libnetinspect.so

libnetinspect.so: src/lib.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f libnetinspect.so

.PHONY: all clean
