//
// main.c
// bpf_dbg_output
//
// Created by reverser on 15/04/17.
// Copyright © 2017 Pedro Vilaça
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without
// limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
// Software, and to permit persons to whom the Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define WARNING_MSG(fmt, ...) fprintf(stderr, "[WARNING] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#if DEBUG == 0
#   define DEBUG_MSG(fmt, ...) do {} while (0)
#else
#   define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)
#endif

struct bpf_insn {
    u_short code;
    u_char  jt;
    u_char  jf;
    uint32_t k;
};

int main(int argc, const char * argv[]) {
    
    uint8_t *buffer = NULL;
    uint32_t buffer_size = 0;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        ERROR_MSG("Failed to open target file %s", argv[1]);
        return EXIT_FAILURE;
    }

    struct stat filestat = {0};
    fstat(fd, &filestat);

    buffer_size = (uint32_t)filestat.st_size;
    if (buffer_size == 0) {
        ERROR_MSG("Input file is zero bytes.");
        return EXIT_FAILURE;
    }
    if (buffer_size % sizeof(struct bpf_insn) != 0) {
        ERROR_MSG("Bad input file! Input file must be only the instructions.");
        return EXIT_FAILURE;
    }

    buffer = (unsigned char*)mmap(0, buffer_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buffer == MAP_FAILED) {
        ERROR_MSG("Failed to mmap target.");
        close(fd);
        return EXIT_FAILURE;
    }
    close(fd);
    
    int total_ins = buffer_size / sizeof(struct bpf_insn);
    printf("Total instructions: %d\n", total_ins);
    printf("---- CUT HERE ----\n");
    printf("load bpf %d,", total_ins);
    uint8_t *cur_buffer = buffer;
    for (int i = 0; i < total_ins-1; i++) {
        struct bpf_insn *insn = (struct bpf_insn*)cur_buffer;
        printf("%d %d %d %u,", insn->code, insn->jt, insn->jf, insn->k);
        cur_buffer += sizeof(struct bpf_insn);
    }
    struct bpf_insn *insn = (struct bpf_insn*)cur_buffer;
    printf("%d %d %d %u\n", insn->code, insn->jt, insn->jf, insn->k);
    printf("---- CUT HERE ----\n");
    return 0;
}
