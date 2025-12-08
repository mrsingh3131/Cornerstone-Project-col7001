#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Required for strcmp
#include <unistd.h>   // Required for fork, execvp, chdir
#include <sys/wait.h> // Required for wait

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

void execute_command(char **args) {
    if (args[0] == NULL) {
        return; // Empty command
    }

    // Built-in: cd
    if (strcmp(args[0], "cd") == 0) {
        if (args[1] == NULL) {
            fprintf(stderr, "myshell: expected argument to \"cd\"\n");
        } else {
            if (chdir(args[1]) != 0) {
                perror("myshell");
            }
        }
        return; // Done. Do not fork.
    }

    // External Commands
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
    } 
    else if (pid == 0) {
        // CHILD 
        execvp(args[0], args);
        
        // If we get here, execvp failed
        perror("myshell"); 
        exit(1);
    } 
    else {
        // PARENT waiting for child to exit
        wait(NULL);
    }
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
        // printf("Parsed commands:\n");
        // for (int j = 0; args[j] != NULL; j++) {
        //     printf("  Arg[%d]: '%s'\n", j, args[j]);
        // }
        // printf("----------------------\n");

        execute_command(args);

    }
    
    return 0;
}