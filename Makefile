# Compiler and Flags
CC = clang #for mac else we would have used gcc

# Flags: -Wall (all warnings), -Wextra (extra warnings), -g (debug info)
CFLAGS = -Wall -Wextra -g

# The name of the final executable
TARGET = shell

# Build Rules
all: $(TARGET)

$(TARGET): shell.c
	$(CC) $(CFLAGS) shell.c -o $(TARGET)

# Clean Rule (removes the executable)
clean:
	rm -f $(TARGET)