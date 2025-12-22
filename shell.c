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
#include <errno.h> // REQUIRED for error checking (ECHILD, EINTR)

#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>

#define MAX_CMD_LEN 1024
#define MAX_ARGS 64
#define HISTORY_SIZE 20
#define MAX_JOBS 20

struct Job {
    int id;       // Job ID (1, 2, 3...)
    pid_t pid;    // Process ID
    int status;   // 1=Running, 0=Stopped
    char cmd[MAX_CMD_LEN];
};

// HISTORY GLOBALS
char history[HISTORY_SIZE][MAX_CMD_LEN];
int history_count = 0;

// TERMINAL GLOBALS
struct termios orig_termios;

void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
    struct termios raw = orig_termios;
    // Disable ICANON (line buffering) and ECHO (auto-printing)
    raw.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

void setup_terminal() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode); // Register cleanup once
    enable_raw_mode();
}

//JOB Control
struct Job job_list[MAX_JOBS];
int job_count = 0;

void add_job(pid_t pid, int status, char *cmd) {
    if (job_count < MAX_JOBS) {
        job_list[job_count].id = job_count + 1;
        job_list[job_count].pid = pid;
        job_list[job_count].status = status;
        strcpy(job_list[job_count].cmd, cmd);
        job_count++;
    }
}

void delete_job(pid_t pid) {
    int found = 0;
    for (int i = 0; i < job_count; i++) {
        if (job_list[i].pid == pid) {
            found = 1;
        }
        if (found && i < job_count - 1) {
            job_list[i] = job_list[i + 1]; // Shift left
            job_list[i].id = i + 1;        // Renumber IDs
        }
    }
    if (found) job_count--;
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
    int pos = 0;   // Total length of the command
    int cursor = 0; // Current cursor position (index)
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
        else if (c == 127 || c == 8) { // BACKSPACE key
            // if (pos > 0) {
            //     pos--;
            //     printf("\b \b"); // Visual backspace
            //     fflush(stdout); // Flush after backspace
            // }
            if (cursor > 0) {
                // 1. Shift memory left to delete the char
                if (cursor < pos) {
                    memmove(&buffer[cursor - 1], &buffer[cursor], pos - cursor);
                }
                
                // 2. Decrement counters
                cursor--;
                pos--;
                buffer[pos] = '\0';

                // 3. Update Visuals
                printf("\b"); // Move back one
                // Print the rest of the string (shifted) + a space at the end to wipe the last char
                printf("%s ", &buffer[cursor]); 
                // Move cursor back to the correct edit position
                // (We printed (len-cursor) chars + 1 space. We need to go back that much)
                for (int i = 0; i < (pos - cursor + 1); i++) printf("\033[D");
                
                fflush(stdout);// Flush after backspace
            }
        } 
        else if (c == '\033') { // ESCAPE sequence (Arrow keys)
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) == 0) continue;
            if (read(STDIN_FILENO, &seq[1], 1) == 0) continue;

            if (seq[0] == '[') {
                // char *target_cmd = NULL;

                if (seq[1] == 'A') { // UP ARROW
                    if (history_index > 0) {
                        history_index--;
                        // target_cmd = history[history_index];
                        // Clear current line visual
                        while (cursor > 0) { printf("\b \b"); cursor--; } // Erase back
                        
                        strcpy(buffer, history[history_index]);
                        pos = strlen(buffer);
                        cursor = pos;
                        printf("%s", buffer);
                        fflush(stdout);
                    }
                } else if (seq[1] == 'B') { // DOWN ARROW
                    if (history_index < history_count) {
                        history_index++;
                        // Clear current line visual
                        while (cursor > 0) { printf("\b \b"); cursor--; }

                        if (history_index < history_count) {
                            strcpy(buffer, history[history_index]);
                        } else {
                            buffer[0] = '\0';
                        }
                        pos = strlen(buffer);
                        cursor = pos;
                        printf("%s", buffer);
                        fflush(stdout);
                    }
                }

                else if (seq[1] == 'C') { // RIGHT ARROW
                    if (cursor < pos) {
                        cursor++;
                        printf("\033[C"); // ANSI code for Move Right
                        fflush(stdout);
                    }
                }
                else if (seq[1] == 'D') { // LEFT ARROW
                    if (cursor > 0) {
                        cursor--;
                        printf("\033[D"); // ANSI code for Move Left
                        fflush(stdout);
                    }
                }
            }
        } 
        else { // Normal Character
            if (pos < MAX_CMD_LEN - 1 && c >= 32 && c <= 126) {
                if (cursor < pos) {
                    memmove(&buffer[cursor + 1], &buffer[cursor], pos - cursor);
                }
                buffer[cursor] = c;
                pos++;
                cursor++;
                buffer[pos] = '\0';

                printf("%c", c); // Print the new char
                
                // Reprint the rest of the line so it doesn't get eaten
                if (cursor < pos) {
                    printf("%s", &buffer[cursor]);
                    // Move visual cursor back to where we are typing
                    for (int i = 0; i < (pos - cursor); i++) printf("\033[D");
                }
                fflush(stdout);  // Flush after typing a letter
            }
        }
    }
}

void handle_sigchld(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    // WNOHANG: Check if any child has exited without blocking
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            delete_job(pid); // Remove from list if finished
        }
    }
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

    // Left Child (cmd1)
    if ((pid1 = fork()) == 0) { // Store PID in pid1
        close(fd[0]);               // Close Read end
        dup2(fd[1], STDOUT_FILENO); // Output -> Pipe Write
        close(fd[1]);               // Close Write end
        
        handle_redirection(args);   // Handle < in first command
        execvp(args[0], args);
        perror("exec cmd1");
        exit(1);
    }

    // Right Child (cmd2)
    if ((pid2 = fork()) == 0) {// Store PID in pid2
        close(fd[1]);               // Close Write end
        dup2(fd[0], STDIN_FILENO);  // Input <- Pipe Read
        close(fd[0]);               // Close Read end
        
        handle_redirection(args2);  // Handle > in second command
        execvp(args2[0], args2);
        perror("exec cmd2");
        exit(1);
    }

    // Parent
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

void run_multistage_pipeline(char **args, int background) {
    int pipefd[2];
    int input_fd = STDIN_FILENO; // Start with standard input
    int cmd_start = 0;
    pid_t pids[MAX_ARGS]; // Track children to wait for them later
    int pid_count = 0;

    disable_raw_mode(); // Restore normal terminal for children

    while (args[cmd_start] != NULL) {
        // 1. Find the next pipe symbol
        int pipe_idx = -1;
        for (int i = cmd_start; args[i] != NULL; i++) {
            if (strcmp(args[i], "|") == 0) {
                pipe_idx = i;
                break;
            }
        }

        // 2. Terminate current command args
        if (pipe_idx != -1) args[pipe_idx] = NULL;

        // 3. Setup Pipe (if not the last command)
        int is_last = (pipe_idx == -1);
        if (!is_last) {
            if (pipe(pipefd) == -1) { perror("pipe"); return; }
        }

        // 4. Fork
        pid_t pid = fork();
        if (pid == 0) {
            // Child Process
            if (input_fd != STDIN_FILENO) {
                dup2(input_fd, STDIN_FILENO);
                close(input_fd);
            }
            if (!is_last) {
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
                close(pipefd[0]); // Close unused read end
            }
            handle_redirection(&args[cmd_start]);
            execvp(args[cmd_start], &args[cmd_start]);
            perror("execvp");
            exit(1);
        } else {
            // Parent Process
            pids[pid_count++] = pid;
            
            if (input_fd != STDIN_FILENO) close(input_fd); // Close used input
            if (!is_last) {
                close(pipefd[1]); // Close write end
                input_fd = pipefd[0]; // Save read end for next command
                cmd_start = pipe_idx + 1; // Move to next command
            } else {
                break; // Finished
            }
        }
    }

    // 5. Wait for all children
    if (!background) {
        for (int i = 0; i < pid_count; i++) {
            waitpid(pids[i], NULL, 0);
        }
    } else {
        printf("[Started pipeline in background]\n");
    }

    enable_raw_mode(); // Restore shell mode
}

// BREAKPOINT HELPERS

struct Breakpoint {
    unsigned long addr;
    unsigned int orig_data; // Store the original 4 bytes
    int active;
};

// Simple storage for up to 10 breakpoints
struct Breakpoint breakpoints[10]; 
int bp_count = 0;

int find_breakpoint_index(unsigned long addr) {
    for (int i = 0; i < bp_count; i++) {
        if (breakpoints[i].addr == addr) {
            return i;
        }
    }
    return -1;
}

// 1. ENABLE (Updated to use task)
void enable_breakpoint(mach_port_t task, struct Breakpoint *bp) {
    // Read original data
    unsigned int data = 0;
    // Note: We use mach_vm_read_overwrite because ptrace's PT_READ_D uses pid, not task.
    // But mixing ptrace and Mach is messy. Let's stick to Mach for memory.
    mach_vm_size_t data_cnt = sizeof(data);
    kern_return_t kr = mach_vm_read_overwrite(task, bp->addr, sizeof(data), (vm_address_t)&data, &data_cnt);
    
    if (kr != KERN_SUCCESS) {
        // Fallback to ptrace if Mach read fails (rare)
        // We assume the caller (run_debug_loop) has the pid if needed,
        printf("Failed to read memory: %d\n", kr);
        return;
    }
    
    bp->orig_data = data;
    unsigned int data_with_trap = (data & ~0xFF) | 0xCC;
    
    // Unlock
    kr = mach_vm_protect(task, bp->addr, sizeof(data_with_trap), 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("Failed to unlock: %d\n", kr);
        return;
    }

    // Write Trap
    kr = mach_vm_write(task, bp->addr, (vm_offset_t)&data_with_trap, sizeof(data_with_trap));
    if (kr != KERN_SUCCESS) printf("Failed to write trap: %d\n", kr);
    else {
        bp->active = 1;
        printf("Breakpoint set at 0x%lx\n", bp->addr);
    }

    // Relock
    mach_vm_protect(task, bp->addr, sizeof(data_with_trap), 0, VM_PROT_READ | VM_PROT_EXECUTE);
}

// 2. DISABLE (Updated to use task)
void disable_breakpoint(mach_port_t task, struct Breakpoint *bp) {
    // Unlock
    kern_return_t kr = mach_vm_protect(task, bp->addr, sizeof(bp->orig_data), 0, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("Failed to unlock for removal: %d\n", kr);
        return;
    }

    // Restore Original
    kr = mach_vm_write(task, bp->addr, (vm_offset_t)&bp->orig_data, sizeof(bp->orig_data));
    if (kr != KERN_SUCCESS) printf("Failed to restore instruction: %d\n", kr);

    // Relock
    mach_vm_protect(task, bp->addr, sizeof(bp->orig_data), 0, VM_PROT_READ | VM_PROT_EXECUTE);
    bp->active = 0;
}

// 3. REGS (Updated to use task)
void print_registers(mach_port_t task) {
    thread_act_port_array_t thread_list;
    mach_msg_type_number_t thread_count;
    kern_return_t kr = task_threads(task, &thread_list, &thread_count);
    
    if (kr != KERN_SUCCESS || thread_count == 0) {
        printf("Error getting threads: %d\n", kr);
        return;
    }

    x86_thread_state64_t state;
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    kr = thread_get_state(thread_list[0], x86_THREAD_STATE64, (thread_state_t)&state, &state_count);
    
    if (kr == KERN_SUCCESS) {
        printf("CPU Registers\n");
        printf("RIP: 0x%llx\n", state.__rip);
        printf("RSP: 0x%llx\n", state.__rsp);
        printf("RBP: 0x%llx\n", state.__rbp);
        printf("RAX: 0x%llx\n", state.__rax);
        printf("---------------------\n");
    }
    
    vm_deallocate(mach_task_self(), (vm_address_t)thread_list, thread_count * sizeof(thread_act_t));
}
void run_debug_loop(pid_t pid) {
    char line[1024];
    int status;
    mach_port_t task;

    printf("Debugger started. Type 'break <addr>', 'continue', or 'quit'.\n");

    while (1) {
        printf("minidbg> ");
        if (fgets(line, sizeof(line), stdin) == NULL) break;
        line[strcspn(line, "\n")] = 0;

        char *command = strtok(line, " ");
        if (command == NULL) continue;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            // If we can't get the port, we can't inspect memory/regs, 
            // but we might still be able to continue/quit via ptrace.
            printf("Warning: Could not get task port (Error %d). Memory/Regs commands may fail.\n", kr);
        }

        // COMMAND: PEEK (Memory Inspection)
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

        // COMMAND: BREAK
        if (strcmp(command, "break") == 0) {
            char *addr_str = strtok(NULL, " ");
            if (addr_str) {
                // Parse hex string to unsigned long
                unsigned long addr = strtoul(addr_str, NULL, 16);
                
                // Add to our list
                breakpoints[bp_count].addr = addr;
                enable_breakpoint(task, &breakpoints[bp_count]);
                bp_count++;
            } else {
                printf("Usage: break <hex_address>\n");
            }
        }

        else if (strcmp(command, "remove") == 0) {
            char *addr_str = strtok(NULL, " ");
            if (addr_str) {
                unsigned long addr = strtoul(addr_str, NULL, 16);
                int index = find_breakpoint_index(addr);
                
                if (index != -1) {
                    // 1. Restore the original instruction (remove trap)
                    disable_breakpoint(task, &breakpoints[index]);
                    printf("Breakpoint removed at 0x%lx\n", addr);

                    // 2. Remove from array (Shift everyone down)
                    for (int i = index; i < bp_count - 1; i++) {
                        breakpoints[i] = breakpoints[i+1];
                    }
                    bp_count--;
                } else {
                    printf("No breakpoint found at 0x%lx\n", addr);
                }
            } else {
                printf("Usage: remove <hex_address>\n");
            }
        }
        // COMMAND: REGS
        else if (strcmp(command, "regs") == 0) {
            print_registers(task);
        }

        else if (strcmp(command, "step") == 0) {
            // 1. Tell ptrace to execute ONE instruction
            ptrace(PT_STEP, pid, (caddr_t)1, 0);

            // 2. Wait for it to finish that one step
            int wait_res = waitpid(pid, &status, 0);

            // 3. Handle Status
            if (wait_res == -1) {
                if (errno == ECHILD) { printf("Child exited normally.\n"); break; }
                else { perror("waitpid"); break; }
            }

            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                break;
            } 
            else if (WIFSTOPPED(status)) {
                // Print where we are after the step
                printf("Stepped.\n");
                print_registers(task); // Helpful to see where we landed
            }
        }

        // COMMAND: CONTINUE
        else if (strcmp(command, "continue") == 0) {
             printf("Resuming execution...\n");
            
            // We are skipping the "rewind and step" logic to avoid Mach API errors.
            ptrace(PT_CONTINUE, pid, (caddr_t)1, 0);
            
            int wait_res = waitpid(pid, &status, 0);

            if (wait_res == -1) {
                if (errno == ECHILD) {
                    printf("Child exited normally.\n");
                    break;
                } else {
                    perror("waitpid");
                    break;
                }
            }

            // Report status
            if (WIFEXITED(status)) {
                printf("Child exited with status %d\n", WEXITSTATUS(status));
                break;
            } 
            else if (WIFSTOPPED(status)) {
                if (WSTOPSIG(status) == SIGTRAP) {
                     printf("Hit breakpoint!\n");
                     // Auto-print registers on break (Optional, but nice!)
                     print_registers(task);
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

    signal(SIGCHLD, SIG_DFL);

    pid_t pid = fork();

    if (pid == 0) {
        // CHILD
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
        // PARENT
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

    signal(SIGCHLD, handle_sigchld);
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

    // JOBS COMMAND
    if (strcmp(args[0], "jobs") == 0) {
        for (int i = 0; i < job_count; i++) {
            printf("[%d] %d %s %s\n", 
                job_list[i].id, 
                job_list[i].pid, 
                (job_list[i].status == 1 ? "Running" : "Stopped"), 
                job_list[i].cmd);
        }
        return;
    }

    // FG COMMAND
    if (strcmp(args[0], "fg") == 0) {
        if (args[1] == NULL) { printf("Usage: fg <job_id>\n"); return; }
        int jid = atoi(args[1]);
        if (jid > 0 && jid <= job_count) {
            pid_t pid = job_list[jid-1].pid;
            printf("Resuming %d in foreground...\n", pid);
            
            // Send SIGCONT in case it was stopped
            kill(pid, SIGCONT);
            
            // Wait for it (Foreground logic)
            disable_raw_mode();
            waitpid(pid, NULL, 0);
            enable_raw_mode();
            
            // It likely exited, so remove it
            delete_job(pid);
        } else {
            printf("Job %d not found\n", jid);
        }
        return;
    }

    // BG COMMAND
    if (strcmp(args[0], "bg") == 0) {
        if (args[1] == NULL) { printf("Usage: bg <job_id>\n"); return; }
        int jid = atoi(args[1]);
        if (jid > 0 && jid <= job_count) {
            pid_t pid = job_list[jid-1].pid;
            printf("Resuming %d in background...\n", pid);
            kill(pid, SIGCONT); // Just continue, don't wait
            job_list[jid-1].status = 1; // Mark running
        } else {
            printf("Job %d not found\n", jid);
        }
        return;
    }

    // EXPORT COMMAND
    if (strcmp(args[0], "export") == 0) {
        if (args[1] == NULL) {
            extern char **environ; // Access the global environment list
            for (char **env = environ; *env != 0; env++) {
                printf("%s\n", *env);
            }
        }
        
        else {
            // Argument provided: Set variable (VAR=VALUE)
            char *key = strtok(args[1], "=");
            char *val = strtok(NULL, ""); // Get everything after the first "="
            
            if (key != NULL) {
                // If val is NULL (e.g. "export VAR="), treat as empty string
                if (val == NULL) val = ""; 
                
                // setenv(key, value, overwrite_flag)
                if (setenv(key, val, 1) != 0) {
                    perror("export");
                }
            } else {
                printf("Usage: export VAR=VALUE\n");
            }
        }
        return; // Done. Do not fork.
    }

    // UNSET COMMAND
    if (strcmp(args[0], "unset") == 0) {
        if (args[1] == NULL) {
            fprintf(stderr, "myshell: expected argument to \"unset\"\n");
        } else {
            if (unsetenv(args[1]) != 0) {
                perror("myshell");
            }
        }
        return; // Done. Do not fork.
    }

        // NEW: Debugger Hook
    if (strcmp(args[0], "debug") == 0) {
        if (args[1] == NULL) {
            printf("Usage: debug <program_name>\n");
        } else {
            disable_raw_mode();
            start_debugger(args);
            enable_raw_mode();
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
    int has_pipe = 0;
    for (int j = 0; args[j]; j++) {
        if (strcmp(args[j], "|") == 0) { has_pipe = 1; break; }
    }
    if (has_pipe) {
        run_multistage_pipeline(args, background);
        return;
    }
    disable_raw_mode(); //Restore normal terminal for the child

    // Standard Commands
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
    } 
    else if (pid == 0) {
        // CHILD 

        signal(SIGINT, SIG_DFL);  // Let child handle Ctrl+C normally
        signal(SIGTSTP, SIG_DFL); // Let child handle Ctrl+Z normally
    
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
            int status;
            
            // 1. Use WUNTRACED to catch Ctrl+Z
            // 2. Save result to check for Race Condition
            pid_t wait_result = waitpid(pid, &status, WUNTRACED);

            if (wait_result > 0) {
                // NORMAL CASE
                if (WIFSTOPPED(status)) {
                    printf("\n[%d] Stopped %s\n", job_count + 1, args[0]);
                    add_job(pid, 0, args[0]); // Add to list as Stopped
                }
            } 
            else if (wait_result == -1) {
                // RACE CONDITION FIX
                if (errno != ECHILD && errno != EINTR) {
                    perror("waitpid");
                }
                // If ECHILD, it means handle_sigchld already cleaned it up. 
                // We do nothing, which is correct.
            }
        } else {
            printf("[Started process %d]\n", pid); // Don't wait
            add_job(pid, 1, args[0]);
        }
    }
    enable_raw_mode(); //Turn Raw Mode back on for your next prompt
}

int main() {
    char command[MAX_CMD_LEN];
    char *args[MAX_ARGS]; // Array to hold the parsed tokens

    // Register signal handlers
    signal(SIGCHLD, handle_sigchld); // this prevents zombies

    signal(SIGINT, handle_sigint);   // Handle Ctrl-C

    signal(SIGTSTP, SIG_IGN); //Ignore Ctrl+Z in shell

    setup_terminal();

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

        // HANDLE !N (HISTORY EXPANSION)
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