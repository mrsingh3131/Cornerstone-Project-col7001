#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Correct header for strcmp

#define MAX_CMD_LEN 1024
#define MAX_ARGS 64

// Takes a raw string "line" and fills the "args" array with pointers to tokens
void parse_input(char *line, char **args) {
    int i = 0;

    // Get the first token split by Space, Tab, and Newline
    args[i] = strtok(line, " \t\n");

    // Loop to get the rest
    while (args[i] != NULL && i < MAX_ARGS - 1) {
        i++;
        // why NULL here? so that strtok can run from where it last left
        args[i] = strtok(NULL, " \t\n"); 
    }
    
    // IMPORTANT: The list of arguments must end with a NULL pointer so execvp knows where to stop reading.
    // This line is so that if there are more than MAX_ARGS argument we still exit from loop and the execvp looks
    // for null so we replace the last argument with NULL
    args[i] = NULL; 
}

int main() {
    char command[MAX_CMD_LEN];
    char *args[MAX_ARGS]; // Array to hold the parsed tokens

    while (1) {
        printf("myshell> ");
        
        // Read input from user
        if (fgets(command, MAX_CMD_LEN, stdin) == NULL) {
            break; // Exit on Ctrl+D
        }

        // Removing the trailing newline character that fgets adds
        command[strcspn(command, "\n")] = 0;

        // Checking for exit command
        if (strcmp(command, "exit") == 0) {
            break;
        }

        // parsing begins
        parse_input(command, args);

        // Debugging parser temporarily
        printf("Parsed commands:\n");
        for (int j = 0; args[j] != NULL; j++) {
            printf("  Arg[%d]: '%s'\n", j, args[j]);
        }
        printf("----------------------\n");
    }
    
    return 0;
}