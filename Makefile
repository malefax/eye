# Linker flag
LDFLAGS = -lpcap

# Targets
all: output

output: netloop.o
	@echo  "Generating netloop file\n"
	gcc netloop.o $(LDFLAGS) -o netloop

netloop.o: netloop.c
	@echo  "Generating object file: netloop.o\n"
	gcc -c netloop.c -o netloop.o

# Install the binary to /usr/local/bin
install: output
	@echo  "Adding to /usr/local/bin/ path\n"
	sudo cp netloop /usr/local/bin/

# Clean up object files and binary
clean:
	@echo  "Removing netloop.o and netloop\n"
	rm -f *.o netloop

# Install dependencies
dependencies:
	@echo  "Installing dependencies\n"
	sudo apt-get install libpcap-dev

# Default target
.PHONY: all clean install dependencies

