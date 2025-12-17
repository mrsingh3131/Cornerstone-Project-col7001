#include <stdio.h>
#include <stdlib.h>
#include <string.h> // Required for strcmp
#include <unistd.h>   // Required for fork, execvp, chdir
#include <sys/wait.h> // Required for wait
#include <fcntl.h> // Required for O_WRONLY, O_CREAT, etc.
#include <signal.h> // Required for signal
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

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

    char msg[] = "\n";
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

// --- BREAKPOINT HELPERS ---

struct Breakpoint {
    unsigned long addr;
    unsigned int orig_data; // Store the original 4 bytes
    int active;
};

// Simple storage for up to 10 breakpoints
struct Breakpoint breakpoints[10]; 
int bp_count = 0;

void enable_breakpoint(pid_t pid, struct Breakpoint *bp) {
    // 1. Read the 4 bytes at the address (PT_READ_D is for Data)
    unsigned int data = ptrace(PT_READ_D, pid, (caddr_t)bp->addr, 0);
    
    // 2. Save original data so we can restore it later
    bp->orig_data = data;
    
    // 3. Modify the lowest byte to 0xCC (INT 3)
    // We use a bitmask: (data & ~0xFF) keeps top 3 bytes, | 0xCC sets bottom byte
    unsigned int data_with_trap = (data & ~0xFF) | 0xCC;
    
    // 4. Write the modified data back
    ptrace(PT_WRITE_D, pid, (caddr_t)bp->addr, data_with_trap);
    bp->active = 1;
    printf("Breakpoint set at 0x%lx\n", bp->addr);
}

void disable_breakpoint(pid_t pid, struct Breakpoint *bp) {
    // 1. Write the original data back to memory
    ptrace(PT_WRITE_D, pid, (caddr_t)bp->addr, bp->orig_data);
    bp->active = 0;
}

void run_debug_loop(pid_t pid) {
    char line[1024];
    int status;
    x86_thread_state64_t state; // To hold registers

    printf("Debugger started. Type 'break <addr>', 'continue', or 'quit'.\n");

    while (1) {
        printf("minidbg> ");
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        line[strcspn(line, "\n")] = 0;

        char *command = strtok(line, " ");
        if (command == NULL) continue;

        // --- COMMAND: BREAK ---
        if (strcmp(command, "break") == 0) {
            char *addr_str = strtok(NULL, " ");
            if (addr_str) {
                // Parse hex string to unsigned long
                unsigned long addr = strtoul(addr_str, NULL, 16);
                
                // Add to our list
                breakpoints[bp_count].addr = addr;
                enable_breakpoint(pid, &breakpoints[bp_count]);
                bp_count++;
            } else {
                printf("Usage: break <hex_address>\n");
            }
        }
        // --- COMMAND: CONTINUE ---
        else if (strcmp(command, "continue") == 0) {
            
            // 1. Check if we are stopped at a breakpoint right now
            ptrace(PT_GETREGS, pid, (caddr_t)&state, 0);
            unsigned long rip = state.__rip; // Get current instruction pointer

            // Check if RIP-1 matches any of our breakpoints
            // (RIP is usually 1 byte past the 0xCC instruction)
            struct Breakpoint *current_bp = NULL;
            for (int i = 0; i < bp_count; i++) {
                if (breakpoints[i].active && breakpoints[i].addr == (rip - 1)) {
                    current_bp = &breakpoints[i];
                    break;
                }
            }

            // 2. If we ARE at a breakpoint, we need to Step-Over it
            if (current_bp != NULL) {
                // A. Rewind RIP by 1 to point at the original instruction
                state.__rip -= 1;
                ptrace(PT_SETREGS, pid, (caddr_t)&state, 0);

                // B. Restore original code (remove 0xCC)
                disable_breakpoint(pid, current_bp);

                // C. Single step (execute that one original instruction)
                ptrace(PT_STEP, pid, (caddr_t)1, 0);
                waitpid(pid, &status, 0); // Wait for step to finish

                // D. Check if child died during step
                if (WIFEXITED(status)) break;

                // E. Re-enable breakpoint (put 0xCC back)
                enable_breakpoint(pid, current_bp);
            }

            // 3. Resume normal execution
            ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
            waitpid(pid, &status, 0);

            // 4. Report status
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                break;
            } 
            else if (WIFSTOPPED(status)) {
                // If stopped by SIGTRAP (5), it's likely a breakpoint
                if (WSTOPSIG(status) == SIGTRAP) {
                     printf("Hit breakpoint!\n");
                } else {
                     printf("Child stopped (Signal: %d)\n", WSTOPSIG(status));
                }
            }
        } 
        else if (strcmp(command, "quit") == 0) {
            kill(pid, SIGKILL);
            break;
        }
    }
}
void start_debugger(char **args) {
    printf("Starting debugger for %s...\n", args[1]);

    pid_t pid = fork();

    if (pid == 0) {
        // --- CHILD ---
        // Arg 3: NULL is fine here.
        // Arg 4: Must be 0 (int), not NULL.
        ptrace(PT_TRACE_ME, 0, NULL, 0);
        
        // Execute the target. We pass &args[1] so the target sees 
        // its own name as argv[0], not "debug"
        execvp(args[1], &args[1]);
        
        perror("execvp");
        exit(1);
    } 
    else if (pid > 0) {
        // --- PARENT ---
        int status;
        
        // Wait for the initial launch stop
        waitpid(pid, &status, WUNTRACED);
        
        if (WIFSTOPPED(status)) {
            // Enter our custom debug loop
            run_debug_loop(pid);
        }
    } 
    else {
        perror("fork");
    }
}

void execute_command(char **args) {
    if (args[0] == NULL) {
        return; // Empty command
    }

        // --- NEW: Debugger Hook ---
    if (strcmp(args[0], "debug") == 0) {
        if (args[1] == NULL) {
            printf("Usage: debug <program_name>\n");
        } else {
            start_debugger(args);
        }
        return; // Return so we don't run the standard fork/exec below
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