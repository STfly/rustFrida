// stack_scan2.c — 用 /proc/<pid>/mem + /proc/<pid>/task/<tid>/stat 避开 ptrace
// 从 stat 读 kstkesp (field 29) 不够, 我们用 syscall 字段里的 sp 值
// 然后 /proc/<pid>/mem seek+read 扫栈内存
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <pid> <tid> <lo> <hi>\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    int tid = atoi(argv[2]);
    uint64_t lo = strtoull(argv[3], NULL, 0);
    uint64_t hi = strtoull(argv[4], NULL, 0);

    // 读 syscall 字段拿 sp/pc
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/syscall", pid, tid);
    FILE *fp = fopen(path, "r");
    if (!fp) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 2; }
    char line[1024];
    if (!fgets(line, sizeof(line), fp)) { fclose(fp); return 3; }
    fclose(fp);

    // 格式可变: 9 字段 (syscall active) 或 3 字段 (-1 sp pc) 或 "running"
    // 最后两个字段永远是 sp pc, 从尾部 parse
    if (strstr(line, "running")) {
        fprintf(stderr, "tid=%d running\n", tid);
        return 4;
    }
    // 拆 tokens, 取末两个
    char *tokens[32] = {0};
    int ntok = 0;
    char *save;
    for (char *t = strtok_r(line, " \t\n", &save); t && ntok < 32; t = strtok_r(NULL, " \t\n", &save)) {
        tokens[ntok++] = t;
    }
    if (ntok < 3) {
        fprintf(stderr, "tid=%d: too few tokens (%d)\n", tid, ntok);
        return 5;
    }
    uint64_t sp = strtoull(tokens[ntok - 2], NULL, 16);
    uint64_t pc = strtoull(tokens[ntok - 1], NULL, 16);

    // 打开 /proc/<pid>/mem
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open %s: %s\n", path, strerror(errno)); return 6; }

    // 扫 256KB 栈 (pthread default stack = 1MB, 线程可能深层嵌套)
    const size_t SCAN = 256 * 1024;
    uint8_t *buf = malloc(SCAN);
    if (lseek(fd, sp, SEEK_SET) < 0) {
        close(fd); free(buf);
        fprintf(stderr, "tid=%d seek fail\n", tid); return 7;
    }
    ssize_t n = read(fd, buf, SCAN);
    close(fd);
    if (n <= 0) { free(buf); fprintf(stderr, "tid=%d read fail\n", tid); return 8; }

    // ARM64 PAC strip: 低 48 位是实际地址, 高位是 PAC 签名
    #define PAC_MASK 0x0000FFFFFFFFFFFFULL
    int hits = 0;
    uint64_t hit_addrs[8] = {0};
    for (size_t i = 0; i + 8 <= (size_t)n; i += 8) {
        uint64_t v;
        memcpy(&v, buf + i, 8);
        uint64_t stripped = v & PAC_MASK;
        if (stripped >= lo && stripped < hi) {
            if (hits < 8) hit_addrs[hits] = v;  // 保留原 (含签名) 形式用于 debug
            hits++;
        }
    }
    free(buf);

    if (hits > 0) {
        printf("tid=%d sp=0x%lx pc=0x%lx hits=%d", tid, sp, pc, hits);
        for (int i = 0; i < hits && i < 8; i++) printf(" %lx", hit_addrs[i]);
        printf("\n");
    }
    return 0;
}
