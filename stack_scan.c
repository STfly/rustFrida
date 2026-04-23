// stack_scan.c — ptrace 附加到目标线程, 读寄存器 + 栈内存, 扫指定范围内的地址
// 用法: stack_scan <pid> <tid> <pool_lo_hex> <pool_hi_hex>
//
// 示例: stack_scan 29642 29685 0x747f96d000 0x747f9d2000
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <elf.h>
#include <linux/elf.h>
#include <sys/user.h>

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <pid> <tid> <pool_lo> <pool_hi>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    pid_t tid = atoi(argv[2]);
    uint64_t lo = strtoull(argv[3], NULL, 0);
    uint64_t hi = strtoull(argv[4], NULL, 0);

    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) < 0) {
        fprintf(stderr, "attach %d: %s\n", tid, strerror(errno));
        return 2;
    }
    int status;
    if (waitpid(tid, &status, __WALL) < 0) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return 3;
    }

    struct user_pt_regs regs;
    struct iovec iov = {&regs, sizeof(regs)};
    if (ptrace(PTRACE_GETREGSET, tid, (void *)NT_PRSTATUS, &iov) < 0) {
        fprintf(stderr, "getregs %d: %s\n", tid, strerror(errno));
        ptrace(PTRACE_DETACH, tid, NULL, NULL);
        return 4;
    }

    printf("=== tid=%d ===\n", tid);
    printf("PC=0x%lx LR=0x%lx SP=0x%lx x19=0x%lx x20=0x%lx x29=0x%lx\n",
           regs.pc, regs.regs[30], regs.sp, regs.regs[19], regs.regs[20], regs.regs[29]);

    // 扫寄存器本身是否落在 pool
    const char *rn[] = {"x0","x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15",
                        "x16","x17","x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","LR"};
    for (int i = 0; i < 31; i++) {
        uint64_t v = regs.regs[i];
        if (v >= lo && v < hi) printf("  REG %s=0x%lx (POOL)\n", rn[i], v);
    }
    if (regs.pc >= lo && regs.pc < hi) printf("  PC=0x%lx (POOL)\n", regs.pc);

    // 扫栈 32KB
    int hits = 0;
    uint64_t sp = regs.sp;
    for (int i = 0; i < 4096 && hits < 40; i++) {
        errno = 0;
        long r = ptrace(PTRACE_PEEKDATA, tid, (void*)(sp + i * 8), NULL);
        if (errno) break;
        uint64_t v = (uint64_t)r;
        if (v >= lo && v < hi) {
            printf("  stack[sp+0x%x] = 0x%lx (POOL)\n", i*8, v);
            hits++;
        }
    }
    printf("  %d pool addrs found in 32KB stack\n", hits);

    ptrace(PTRACE_DETACH, tid, NULL, NULL);
    return 0;
}
