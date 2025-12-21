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
#include <termios.h> // REQUIRED for raw mode (Arrow keys)
#include <ctype.h>   // REQUIRED for isdigit

#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>

#define MAX_CMD_LEN 1024
#define MAX_ARGS 64
#define HISTORY_SIZE 20

// HISTORY GLOBALS
char history[HISTORY_SIZE][MAX_CMD_LEN];
int history_count = 0;

// TERMINAL GLOBALS
struct termios orig_termios;

void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode); // Ensure we reset terminal on exit

    struct termios raw = orig_termios;
    // Disable ICANON (line buffering) and ECHO (auto-printing)
    raw.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

// HISTORY FUNCTIONS
void add_to_history(const char *cmd) {
    if (strlen(cmd) == 0) return; // Don't save empty commands

    // Check if it's a duplicate of the immediate last command
    if (history_count > 0 && strcmp(history[(history_count - 1) % HISTORY_SIZE], cmd) == 0) {
        return;
    }

    if (history_count < HISTORY_SIZE) {
        strcpy(history[history_count], cmd);
    } else {
        // For a simple circular implementation in this context, 
        // we will just shift everything left to keep indices consistent 1..20
        // This is easier for the !N command logic.
        for (int i = 1; i < HISTORY_SIZE; i++) {
            strcpy(history[i-1], history[i]);
        }
        strcpy(history[HISTORY_SIZE - 1], cmd);
    }
    // We only increment count up to HISTORY_SIZE for this simple sliding window implementation
    // However, to keep "total commands" accurate for !N, we can just cap the visual list
    if (history_count < HISTORY_SIZE) history_count++;
}

// CUSTOM INPUT READER (Handles Arrow Keys)
void read_input(char *buffer) {
    int pos = 0;
    int history_index = history_count; // Start "below" the last history item
    char c;

    buffer[0] = '\0';

    while (1) {
        if (read(STDIN_FILENO, &c, 1) == -1) break;

        if (c == '\n') { // ENTER key
            buffer[pos] = '\0';
            printf("\n");
            break;
        } 
        else if (c == 127) { // BACKSPACE key
            if (pos > 0) {
                pos--;
                printf("\b \b"); // Visual backspace
                fflush(stdout); // Flush after backspace
            }
        } 
        else if (c == '\033') { // ESCAPE sequence (Arrow keys)
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) == 0) continue;
            if (read(STDIN_FILENO, &seq[1], 1) == 0) continue;

            if (seq[0] == '[') {
                char *target_cmd = NULL;

                if (seq[1] == 'A') { // UP ARROW
                    if (history_index > 0) {
                        history_index--;
                        target_cmd = history[history_index];
                    }
                } else if (seq[1] == 'B') { // DOWN ARROW
                    if (history_index < history_count) {
                        history_index++;
                        if (history_index < history_count) {
                            target_cmd = history[history_index];
                        } else {
                            target_cmd = ""; // Back to empty
                        }
                    }
                }

                // If we moved, update the screen
                if (target_cmd != NULL) {
                    // Erase current line
                    while (pos > 0) {
                        printf("\b \b");
                        pos--;
                    }
                    // Copy new command
                    strcpy(buffer, target_cmd);
                    pos = strlen(buffer);
                    printf("%s", buffer);
                    fflush(stdout); // Flush after history replace
                }
            }
        } 
        else { // Normal Character
            if (pos < MAX_CMD_LEN - 1) {
                buffer[pos++] = c;
                printf("%c", c); // Echo manually
                fflush(stdout);  // Flush after typing a letter
            }
        }
    }
}

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
    // 1. Read the 4 bytes at the address
    unsigned int data = ptrace(PT_READ_D, pid, (caddr_t)bp->addr, 0);
    
    // 2. Save original data
    bp->orig_data = data;
    
    // 3. Modify the lowest byte to 0xCC (INT 3)
    unsigned int data_with_trap = (data & ~0xFF) | 0xCC;
    
    // 4. Get the task port
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    
    if (kr != KERN_SUCCESS) {
        perror("Failed to get task for pid");
        return;
    }

    // --- STEP 5: CHANGE PERMISSIONS (Unlock) ---
    // VM_PROT_COPY forces a "Copy-on-Write" so we don't corrupt the actual binary file
    kr = mach_vm_protect(task, bp->addr, sizeof(data_with_trap), 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("Failed to change memory protection (Unlock): %d\n", kr);
        return;
    }

    // --- STEP 6: WRITE DATA ---
    kr = mach_vm_write(task, bp->addr, (vm_offset_t)&data_with_trap, sizeof(data_with_trap));
    if (kr != KERN_SUCCESS) {
        printf("Failed to write trap instruction: %d\n", kr);
    } else {
        bp->active = 1;
        printf("Breakpoint set at 0x%lx\n", bp->addr);
    }

    // --- STEP 7: RESTORE PERMISSIONS (Relock) ---
    // Restore to Read+Execute so the CPU can run it
    mach_vm_protect(task, bp->addr, sizeof(data_with_trap), 0, VM_PROT_READ | VM_PROT_EXECUTE);
}
void disable_breakpoint(pid_t pid, struct Breakpoint *bp) {
    // 1. Write the original data back using Mach API
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    
    if (kr == KERN_SUCCESS) {
        kr = mach_vm_write(task, bp->addr, (vm_offset_t)&bp->orig_data, sizeof(bp->orig_data));
    }

    if (kr != KERN_SUCCESS) {
         perror("Failed to remove breakpoint");
    }
    
    bp->active = 0;
}

// Helper to print registers on macOS
void print_registers(pid_t pid) {
    // 1. Get the Mach task port for the process
    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    
    // --- GRACEFUL ERROR HANDLING ---
    if (kr != KERN_SUCCESS) {
        // We failed to get the task. Check the error code.
        printf("Error: Could not get task port (Error %d)\n", kr);
        
        // Suggest the fix to the user
        if (kr == KERN_FAILURE) {
            printf("Hint: You likely need to run this debugger with 'sudo' to inspect registers on macOS.\n");
        }
        return;
    }

    // 2. Get the first thread in the task
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kr = task_threads(task, &thread_list, &thread_count);
    if (kr != KERN_SUCCESS || thread_count == 0) {
        printf("Error getting threads\n");
        return;
    }

    // 3. Get the state of that thread
    x86_thread_state64_t state;
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread_list[0], x86_THREAD_STATE64, 
                         (thread_state_t)&state, &state_count);
    
    if (kr == KERN_SUCCESS) {
        printf("--- CPU Registers ---\n");
        printf("RIP: 0x%llx\n", state.__rip);
        printf("RSP: 0x%llx\n", state.__rsp);
        printf("RBP: 0x%llx\n", state.__rbp);
        printf("RAX: 0x%llx\n", state.__rax);
        printf("---------------------\n");
    } else {
        printf("Error getting thread state\n");
    }
    
    // Clean up memory
    vm_deallocate(mach_task_self(), (vm_address_t)thread_list, 
                 thread_count * sizeof(thread_act_t));
}

void run_debug_loop(pid_t pid) {
    char line[1024];
    int status;
    // Removed: x86_thread_state64_t state; (Not needed for simple resume)

    printf("Debugger started. Type 'break <addr>', 'continue', or 'quit'.\n");

    while (1) {
        printf("minidbg> ");
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        line[strcspn(line, "\n")] = 0;

        char *command = strtok(line, " ");
        if (command == NULL) continue;

        // --- COMMAND: PEEK (Memory Inspection) ---
        else if (strcmp(command, "peek") == 0) {
            char *addr_str = strtok(NULL, " ");
            if (addr_str) {
                unsigned long addr = strtoul(addr_str, NULL, 16);
                
                // Read 4 bytes from the address
                // Note: ptrace returns the data directly as the return value
                unsigned int data = ptrace(PT_READ_D, pid, (caddr_t)addr, 0);
                
                printf("Data at 0x%lx: 0x%x\n", addr, data);
            } else {
                printf("Usage: peek <hex_address>\n");
            }
        }

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

        // --- COMMAND: REGS ---
        else if (strcmp(command, "regs") == 0) {
            print_registers(pid);
        }
        // --- COMMAND: CONTINUE ---
        else if (strcmp(command, "continue") == 0) {
             printf("Resuming execution...\n");
            
            // Simplified for macOS: Just resume. 
            // We are skipping the "rewind and step" logic to avoid Mach API errors.
            ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
            
            waitpid(pid, &status, 0);

            // Report status
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                break;
            } 
            else if (WIFSTOPPED(status)) {
                if (WSTOPSIG(status) == SIGTRAP) {
                     printf("Hit breakpoint!\n");
                     // Auto-print registers on break (Optional, but nice!)
                     print_registers(pid);
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
    // HISTORY COMMAND
    if (strcmp(args[0], "history") == 0) {
        for(int i = 0; i < history_count; i++) {
            printf("  %d  %s\n", i + 1, history[i]);
        }
        return;
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
    // signal(SIGCHLD, handle_sigchld); // this prevents zombies

    signal(SIGINT, handle_sigint);   // Handle Ctrl-C

    enable_raw_mode(); // Turn on arrow keys support

    // while (1) {
    //     printf("myshell> ");
        
    //     // Read input from user
    //     if (fgets(command, MAX_CMD_LEN, stdin) == NULL) {
    //         break; // Exit on Ctrl+D
    //     }

    //     // Removing the trailing newline character that fgets adds
    //     command[strcspn(command, "\n")] = 0;

    //     // Checking for exit command
    //     if (strcmp(command, "exit") == 0) {
    //         break;
    //     }

    //     // parsing begins
    //     parse_quoted_input(command, args);

    //     // Debugging parser temporarily
    //     // printf("Parsed commands:\n");
    //     // for (int j = 0; args[j] != NULL; j++) {
    //     //     printf("  Arg[%d]: '%s'\n", j, args[j]);
    //     // }
    //     // printf("----------------------\n");

    //     execute_command(args);

    // }

    while (1) {
        printf("myshell> ");
        fflush(stdout); 
        
        read_input(command); // Custom reader

        if (strcmp(command, "exit") == 0) break;

        // --- HANDLE !N (HISTORY EXPANSION) ---
        if (command[0] == '!') {
            int target_idx = -1;
            if (command[1] == '!') {
                // !! runs the last command
                if (history_count > 0) target_idx = history_count;
            } else if (isdigit(command[1])) {
                // !N runs Nth command
                target_idx = atoi(&command[1]);
            }

            if (target_idx > 0 && target_idx <= history_count) {
                // Replace current command with historical one
                strcpy(command, history[target_idx - 1]);
                printf("The command to be run is: %s\n", command); // Print it so user sees what ran
            } else {
                printf("myshell: command not found in history\n");
                continue;
            }
        }

        add_to_history(command);
        parse_quoted_input(command, args);
        execute_command(args);
    }
    
    return 0;
}