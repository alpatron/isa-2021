MKDIR_P=mkdir -p
CC=g++
CFLAGS=-std=c++17 -g -Wall -Wextra -pedantic
BUILDDIR=./bin

.PHONY: directories

all: directories secret

directories: ${BUILDDIR}
${BUILDDIR}:
		${MKDIR_P} ${BUILDDIR}

secret:
	$(CC) $(CFLAGS) -o $(BUILDDIR)/secret argumentParsing.cpp addressResolution.cpp receiveFile.cpp sendFile.cpp tools.cpp main.cpp

clean:
	rm -rf $(BUILDDIR)