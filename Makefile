# Compiler and Flags
CC = clang #for mac else we would have used gcc

# Flags: -Wall (all warnings), -Wextra (extra warnings), -g (debug info)
CFLAGS = -Wall -Wextra -g

# The names of the final executables
TARGET_SHELL = shell
TARGET_TEST = target

# Build Rules
# "all" defines what gets built when you type "make"
all: $(TARGET_SHELL) $(TARGET_TEST)

$(TARGET_SHELL): shell.c
	$(CC) $(CFLAGS) -o $(TARGET_SHELL) shell.c

$(TARGET_TEST): target.c
	$(CC) $(CFLAGS) -o $(TARGET_TEST) target.c

# Clean Rule (removes the executables)
clean:
	rm -f $(TARGET_SHELL) $(TARGET_TEST)