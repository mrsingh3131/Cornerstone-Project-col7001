#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Required for strcmp
#include <unistd.h>   // Required for fork, execvp, chdir
#include <sys/wait.h> // Required for wait
#include <fcntl.h> // Required for O_WRONLY, O_CREAT, etc.
#include <signal.h> // Required for signal

#define MAX_CMD_LEN 1024
#define MAX_ARGS 64

void handle_sigchld(int sig) {
    (void)sig; // Silence the unused parameter warning
    // Clean up any child processes that have finished
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

void handle_sigint(int sig) {
    (void)sig; // Silence the unused parameter warning
    // Write a new line so the ^C doesn't mess up the formatting

    char msg[] = "\nmyshell> ";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    // Protip We use write instead of printf because printf is not "async-signal-safe" 
    // printf can cause deadlocks if interrupted. write is safe.
}

// parse_quoted_input (Quoted Strings) 
// Scanning: Move forward until we find a non-space character which will be our start of token.
// Reading: Move forward.
//     If we hit a Space and we are not inside quotes we see this as end of token.
//     If we hit a Quote " then we toggle the in_quotes flag and remove the quote character.
//     If we hit a Space and we are inside quotes then we keep reading and treat space as a normal letter.
void parse_quoted_input(char *line, char **args) {
    int arg_count = 0;
    char *ptr = line;
    int in_quotes = 0;
    
    // Clear args array first (good hygiene)
    for(int i=0; i<MAX_ARGS; i++) args[i] = NULL;

    while (*ptr != '\0' && arg_count < MAX_ARGS - 1) {
        // 1. Skip leading whitespace (only if NOT in quotes)
        while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n') {
            *ptr = '\0'; // Null-terminate the previous token
            ptr++;
        }
        
        if (*ptr == '\0') break; // End of line

        // 2. Check for quote at start of token
        if (*ptr == '"') {
            in_quotes = 1;
            ptr++; // Skip the opening quote
        } 
        
        // Mark the start of the current argument
        args[arg_count] = ptr; 
        
        // 3. Scan for the end of this argument
        while (*ptr != '\0') {
            if (in_quotes) {
                if (*ptr == '"') {
                    // Closing quote found!
                    in_quotes = 0;
                    *ptr = '\0'; // Terminate string here
                    ptr++;
                    break; // Move to next token
                }
            } else {
                if (*ptr == ' ' || *ptr == '\t' || *ptr == '\n') {
                    // Space found (and not in quotes) -> End of arg
                    break; 
                }
            }
            ptr++;
        }
        
        arg_count++;
    }
    args[arg_count] = NULL;
}

void handle_redirection(char **args) {
    for (int i = 0; args[i] != NULL; i++) {
        
        // Output Redirection (>)
        if (strcmp(args[i], ">") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "Syntax error: expected file after >\n");
                exit(1);
            }
            
            // Open file with flags + permissions (0644)
            // Flag 1: Open for writing only.
            // Flag 2: Create if missing.
            // Flag 3: Empty the file if it exists.
            int fd = open(args[i+1], O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                perror("open failed");
                exit(1);
            }
            
            // Redirect Standard Output (1) to this file
            dup2(fd, STDOUT_FILENO); 
            close(fd); // Close the original file descriptor, we don't need it anymore
            
            args[i] = NULL; // Cut the command here so execvp doesn't see ">"
        }
        
        // Input Redirection (<)
        else if (strcmp(args[i], "<") == 0) {
            if (args[i+1] == NULL) {
                fprintf(stderr, "Syntax error: expected file after <\n");
                exit(1);
            }
            
            // Open for Reading Only
            int fd = open(args[i+1], O_RDONLY);
            if (fd < 0) {
                perror("open failed");
                exit(1);
            }
            
            // Redirect Standard Input (0) to this file
            dup2(fd, STDIN_FILENO);
            close(fd);
            
            args[i] = NULL; // Cut the command
        }
    }
}

// Handles "cmd1 | cmd2"
void run_pipeline(char **args, int pipe_idx, int background) {
    int fd[2];
    pid_t pid1, pid2; // Variables to store PIDs so we can kill only the specific PIDs
    if (pipe(fd) == -1) { perror("pipe"); return; }

    args[pipe_idx] = NULL; // Split the args array
    char **args2 = &args[pipe_idx + 1];

    // --- Left Child (cmd1) ---
    if ((pid1 = fork()) == 0) { // Store PID in pid1
        close(fd[0]);               // Close Read end
        dup2(fd[1], STDOUT_FILENO); // Output -> Pipe Write
        close(fd[1]);               // Close Write end
        
        handle_redirection(args);   // Handle < in first command
        execvp(args[0], args);
        perror("exec cmd1");
        exit(1);
    }

    // --- Right Child (cmd2) ---
    if ((pid2 = fork()) == 0) {// Store PID in pid2
        close(fd[1]);               // Close Write end
        dup2(fd[0], STDIN_FILENO);  // Input <- Pipe Read
        close(fd[0]);               // Close Read end
        
        handle_redirection(args2);  // Handle > in second command
        execvp(args2[0], args2);
        perror("exec cmd2");
        exit(1);
    }

    // --- Parent ---
    close(fd[0]);
    close(fd[1]);
    
    if (!background) {
        // wait(NULL);
        // wait(NULL);

        // FIX: Wait for specific PIDs
        waitpid(pid1, NULL, 0);
        waitpid(pid2, NULL, 0);

    } else {
        printf("[Started pipeline in background]\n");
    }
}

void execute_command(char **args) {
    if (args[0] == NULL) {
        return; // Empty command
    }

    // Background Detection Flag
    int background = 0;
    int i = 0;
    while (args[i] != NULL){
        i++;
    }

    // Check if the very last argument is "&"
    if (i > 0 && strcmp(args[i-1], "&") == 0) {
        background = 1;
        args[i-1] = NULL; // Remove "&" so the command doesn't see it
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

    // Pipeline Detection 
    for (int j = 0; args[j] != NULL; j++) {
        if (strcmp(args[j], "|") == 0) {
            run_pipeline(args, j, background);
            return; // Pipeline handled, return immediately
        }
    }

    // Standard Commands
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
    } 
    else if (pid == 0) {
        // CHILD 
    
        // Handle Redirection first then execute
        handle_redirection(args);

        execvp(args[0], args);

        // If we get here, execvp failed
        perror("myshell"); 
        exit(1);
    } 
    else {
        // PARENT waiting for child to exit
        if (background == 0) {
            // FIX: Wait ONLY for this specific child (pid)
            // If the signal handler already reaped it, this returns -1 (which is fine, we move on).
            waitpid(pid, NULL, 0);
            // wait(NULL); // Wait for foreground process
        } else {
            printf("[Started process %d]\n", pid); // Don't wait
        }
    }
}

int main() {
    char command[MAX_CMD_LEN];
    char *args[MAX_ARGS]; // Array to hold the parsed tokens

    // Register signal handlers
    signal(SIGCHLD, handle_sigchld); // this prevents zombies

    signal(SIGINT, handle_sigint);   // Handle Ctrl-C


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
        parse_quoted_input(command, args);

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