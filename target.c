// target.c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void foo() {
    printf("Inside foo! The debugger works!\n");
}

int main() {
    printf("Target started.\n");
    
    // 1. Reveal the address of 'foo' (this changes every time!)
    printf("ADDRESS_OF_FOO: %p\n", foo);
    
    // 2. Pause ourselves so the debugger (shell) can take control
    printf("Pausing for debugger... (raising SIGTRAP)\n");
    raise(SIGTRAP); 
    
    // 3. Call foo (This is where we want to break)
    foo();
    
    printf("Target finished.\n");
    return 0;
}