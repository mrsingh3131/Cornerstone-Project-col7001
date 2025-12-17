========================================================================
                   MINIDBG - Custom Shell & Debugger
========================================================================

DESCRIPTION
-----------
This project implements a custom command-line shell (from Lab 1) integrated 
with a functional debugger (Lab 2) using the ptrace API. It allows users to 
navigate the file system, execute standard programs, and debug target 
binaries with breakpoint capabilities.

COMPILATION
-----------
To compile the shell, debugger, and the test target program, run:

    $ make

This will generate the following executables:
  - shell   (The main shell/debugger program)
  - target  (A sample program to test debugging features)

USAGE
-----
1. Start the shell:
   $ sudo ./shell

   *Note: 'sudo' is often required on macOS/Linux to grant ptrace permissions 
    for inspecting registers and memory.*

2. Once inside the shell (myshell>), you can run standard commands or 
   start the debugger.

3. To debug a program:
   myshell> debug ./target

DEBUGGER COMMANDS (minidbg>)
----------------------------
Once the debugger is running, use the following commands:

  * break <address> : Set a breakpoint at a specific hex address.
                      Example: break 0x100000f63

  * continue        : Resume execution until the next breakpoint or exit.

  * regs            : Inspect the current state of CPU registers 
                      (RIP, RSP, RBP, RAX, etc.).

  * peek <address>  : Inspect the memory content (4 bytes) at a specific 
                      address.

  * quit            : Exit the debugger and return to the shell.

SHELL COMMANDS (Lab 1 Features)
-------------------------------
The shell supports standard system operations:

  * cd <path>       : Change the current directory.
  * exit            : Terminate the shell.
  * <program>       : Execute any standard binary (e.g., ls -la, pwd).
  
  [Additional Features]
  * Redirection     : Support for '>' (output) and '<' (input).
  * Pipelines       : Support for '|' to chain commands (e.g., ls | grep c).

CLEANUP
-------
To remove compiled binaries and object files:

    $ make clean

========================================================================