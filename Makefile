MKDIR_P=mkdir -p
CC=g++
CFLAGS=-g -Wall -Wextra -pedantic
BUILDDIR=./bin

.PHONY: directories

all: directories secret

directories: ${BUILDDIR}
${BUILDDIR}:
		${MKDIR_P} ${BUILDDIR}

secret:
	$(CC) $(CFLAGS) -o $(BUILDDIR)/secret main.cpp argumentParsing.cpp

clean:
	rm -rf $(BUILDDIR)