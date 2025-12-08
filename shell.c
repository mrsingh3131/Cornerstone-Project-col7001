#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Correct header for strcmp

#define MAX_CMD_LEN 1024

int main() {
    char command[MAX_CMD_LEN];

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
    }
    
    return 0;
}