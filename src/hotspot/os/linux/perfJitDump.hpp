/*
 * Copyright (c) 2024, Oracle and/or its affiliates. All rights reserved.
 * Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#ifndef SHARE_CODE_PERFJITDUMP_HPP
#define SHARE_CODE_PERFJITDUMP_HPP

#define JITHEADER_MAGIC       0x4A695444

#define JITHEADER_VERSION 1

struct jitheader {
    uint32_t magic;      /* characters "jItD" */
    uint32_t version;    /* header version */
    uint32_t total_size; /* total size of header */
    uint32_t elf_mach;   /* elf mach target */
    uint32_t pad1;       /* reserved */
    uint32_t pid;        /* JIT process id */
    uint64_t timestamp;  /* timestamp */
    uint64_t flags;      /* flags */
};

enum jit_record_type {
    JIT_CODE_LOAD           = 0,
    JIT_CODE_MOVE           = 1,
    JIT_CODE_DEBUG_INFO     = 2,
    JIT_CODE_CLOSE          = 3,
    JIT_CODE_UNWINDING_INFO = 4,
    JIT_CODE_MAX
};

struct jr_prefix {
    uint32_t id;
    uint32_t total_size;
    uint64_t timestamp;
};

struct jr_code_load {
    struct jr_prefix p;

    uint32_t pid;
    uint32_t tid;
    uint64_t vma;
    uint64_t code_addr;
    uint64_t code_size;
    uint64_t code_index;
};

struct jr_code_debug_info {
    struct jr_prefix p;

    uint64_t code_addr;
    uint64_t nr_entry;
};

struct debug_entry {
    uint64_t addr;
    int lineno;        /* source line number starting at 1 */
    int discrim;        /* column discriminator, 0 is default */
};

struct jr_code_close {
    struct jr_prefix p;
};

typedef struct {
    unsigned long    pc;
    int        line_number;
    int        discrim; /* discriminator -- 0 for now */
    jmethodID    methodID;
} jvmti_line_info_t;

class PerfJitDumpAgent
{
 public:
  static bool open_marker_file(int fd);
  static bool create();
  static void close();

 private:
  static void close_marker_file();
};


#endif // SHARE_CODE_PERFJITDUMP_HPP
