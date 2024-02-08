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
 *
 */

#include "precompiled.hpp"
#include "jvm.h"
#include "logging/log.hpp"
#include "prims/jvmtiEnvBase.hpp"
#include "perfJitDump.hpp"

#include <sys/mman.h>


static bool has_line_numbers = false;

#define JIT_LANG "java"

#define PATH_MAX 4096
static char jit_path[PATH_MAX];
static void *marker_addr;

static FILE *jvmti_agent = nullptr;

#define NSEC_PER_SEC    1000000000
static int perf_clk_id = CLOCK_MONOTONIC;

static inline uint64_t
timespec_to_ns(const struct timespec *ts)
{
        return ((uint64_t) ts->tv_sec * NSEC_PER_SEC) + ts->tv_nsec;
}

static inline uint64_t perf_get_timestamp()
{
    struct timespec ts;
    int ret;

    ret = clock_gettime(perf_clk_id, &ts);
    if (ret)
        return 0;

    return timespec_to_ns(&ts);
}

static int create_jit_cache_dir()
{
    char str[32];
    const char *base, *p;
    struct tm tm;
    time_t t;
    int ret;

    time(&t);
    localtime_r(&t, &tm);

    base = getenv("JITDUMPDIR");
    if (!base)
        base = getenv("HOME");
    if (!base)
        base = ".";

    strftime(str, sizeof(str), "java-jit-%Y%m%d", &tm);

    ret = snprintf(jit_path, PATH_MAX, "%s/.debug/", base);
    if (ret >= PATH_MAX) {
        log_trace(dump)("jvmti: cannot generate jit cache dir because %s/.debug/"
            " is too long, please check the cwd, JITDUMPDIR, and"
            " HOME variables", base);
        return -1;
    }
    ret = mkdir(jit_path, 0755);
    if (ret == -1) {
        if (errno != EEXIST) {
            log_trace(dump)("jvmti: cannot create jit cache dir %s", jit_path);
            return -1;
        }
    }

    ret = snprintf(jit_path, PATH_MAX, "%s/.debug/jit", base);
    if (ret >= PATH_MAX) {
        log_trace(dump)("jvmti: cannot generate jit cache dir because"
            " %s/.debug/jit is too long, please check the cwd,"
            " JITDUMPDIR, and HOME variables", base);
        return -1;
    }
    ret = mkdir(jit_path, 0755);
    if (ret == -1) {
        if (errno != EEXIST) {
            log_trace(dump)("jvmti: cannot create jit cache dir %s", jit_path);
            return -1;
        }
    }

    ret = snprintf(jit_path, PATH_MAX, "%s/.debug/jit/%s.XXXXXXXX", base, str);
    if (ret >= PATH_MAX) {
        log_trace(dump)("jvmti: cannot generate jit cache dir because"
            " %s/.debug/jit/%s.XXXXXXXX is too long, please check"
            " the cwd, JITDUMPDIR, and HOME variables",
            base, str);
        return -1;
    }
    p = mkdtemp(jit_path);
    if (p != jit_path) {
        log_trace(dump)("jvmti: cannot create jit cache dir %s", jit_path);
        return -1;
    }

    return 0;
}

static int get_e_machine(struct jitheader *hdr)
{
    ssize_t sret;
    char id[16];
    int fd, ret = -1;
    struct {
        uint16_t e_type;
        uint16_t e_machine;
    } info;

    fd = open("/proc/self/exe", O_RDONLY);
    if (fd == -1)
        return -1;

    sret = read(fd, id, sizeof(id));
    if (sret != sizeof(id))
        goto error;

    /* check ELF signature */
    if (id[0] != 0x7f || id[1] != 'E' || id[2] != 'L' || id[3] != 'F')
        goto error;

    sret = read(fd, &info, sizeof(info));
    if (sret != sizeof(info))
        goto error;

    hdr->elf_mach = info.e_machine;
    ret = 0;
error:
    close(fd);
    return ret;
}

static FILE *jvmti_open(void)
{
    char dump_path[PATH_MAX];
    struct jitheader header;
    int fd, ret;
    FILE *fp;

    /*
     * check if clockid is supported
     */
    if (!perf_get_timestamp()) {
        log_trace(dump)("jvmti: kernel does not support %d clock id", perf_clk_id);
    }

    memset(&header, 0, sizeof(header));

    /*
     * jitdump file dir
     */
    if (create_jit_cache_dir() < 0)
        return NULL;

    /*
     * jitdump file name
     */
    ret = snprintf(dump_path, PATH_MAX, "%s/jit-%i.dump", jit_path, getpid());
    if (ret >= PATH_MAX) {
        log_trace(dump)("jvmti: cannot generate jitdump file full path because"
            " %s/jit-%i.dump is too long, please check the cwd,"
            " JITDUMPDIR, and HOME variables", jit_path, getpid());
        return NULL;
    }

    fd = open(dump_path, O_CREAT|O_TRUNC|O_RDWR, 0666);
    if (fd == -1)
        return NULL;

    /*
     * create perf.data maker for the jitdump file
     */
    if (!PerfJitDumpAgent::open_marker_file(fd)) {
        log_trace(dump)("jvmti: failed to create marker file");
        return NULL;
    }

    fp = fdopen(fd, "w+");
    if (!fp) {
        log_trace(dump)("jvmti: cannot create %s", dump_path);
        close(fd);
        goto error;
    }

    log_trace(dump)("jvmti: jitdump in %s", dump_path);

    if (get_e_machine(&header)) {
        log_trace(dump)("get_e_machine failed\n");
        goto error;
    }

    header.magic      = JITHEADER_MAGIC;
    header.version    = JITHEADER_VERSION;
    header.total_size = sizeof(header);
    header.pid        = getpid();

    header.timestamp = perf_get_timestamp();

    if (!fwrite(&header, sizeof(header), 1, fp)) {
        log_trace(dump)("jvmti: cannot write dumpfile header");
        goto error;
    }
    return fp;
error:
    fclose(fp);
    return NULL;
}

static int jvmti_write_code(FILE *agent, char const *sym, void const *code, unsigned int const size)
{
    static int code_generation = 1;
    struct jr_code_load rec;
    size_t sym_len;
    FILE *fp = agent;
    int ret = -1;

    /* don't care about 0 length function, no samples */
    if (size == 0)
        return 0;

    if (!fp) {
        log_trace(dump)("jvmti: invalid fd in write_native_code");
        return -1;
    }

    sym_len = strlen(sym) + 1;

    rec.p.id           = JIT_CODE_LOAD;
    rec.p.total_size   = sizeof(rec) + sym_len;
    rec.p.timestamp    = perf_get_timestamp();

    rec.code_size  = size;
    rec.vma        = (uint64_t)code;
    rec.code_addr  = (uint64_t)code;
    rec.pid           = os::current_process_id();
    rec.tid           = os::current_thread_id();

    if (code)
        rec.p.total_size += size;

    /*
     * If JVM is multi-threaded, multiple concurrent calls to agent
     * may be possible, so protect file writes
     */
    flockfile(fp);

    /*
     * get code index inside lock to avoid race condition
     */
    rec.code_index = code_generation++;

    ret = fwrite_unlocked(&rec, sizeof(rec), 1, fp);
    fwrite_unlocked(sym, sym_len, 1, fp);

    if (code)
        fwrite_unlocked(code, size, 1, fp);

    funlockfile(fp);

    ret = 0;

    return ret;
}

int jvmti_write_debug_info(FILE *agent, uint64_t code,
    int nr_lines, jvmti_line_info_t *li,
    const char * const * file_names)
{
    size_t sret, len, size, flen = 0;

    // no entry to write
    if (!nr_lines)
        return 0;

    assert(agent, "jvmti: invalid fd in write_debug_info");

    for (int i = 0; i < nr_lines; ++i) {
        flen += strlen(file_names[i]) + 1;
    }

    struct jr_code_debug_info rec;
    rec.p.id        = JIT_CODE_DEBUG_INFO;
    size            = sizeof(rec);
    rec.p.timestamp = perf_get_timestamp();
    rec.code_addr   = (uint64_t)code;
    rec.nr_entry    = nr_lines;

    /*
     * on disk source line info layout:
     * uint64_t : addr
     * int      : line number
     * int      : column discriminator
     * file[]   : source file name
     */
    size += nr_lines * sizeof(struct debug_entry);
    size += flen;
    rec.p.total_size = size;

    /*
     * If JVM is multi-threaded, multiple concurrent calls to agent
     * may be possible, so protect file writes
     */
    flockfile(agent);

    sret = fwrite_unlocked(&rec, sizeof(rec), 1, agent);
    if (sret != 1)
        goto error;

    for (int i = 0; i < nr_lines; i++) {
        uint64_t addr = (uint64_t)li[i].pc;
        len  = sizeof(addr);
        sret = fwrite_unlocked(&addr, len, 1, agent);
        if (sret != 1)
            goto error;

        len  = sizeof(li[0].line_number);
        sret = fwrite_unlocked(&li[i].line_number, len, 1, agent);
        if (sret != 1)
            goto error;

        len  = sizeof(li[0].discrim);
        sret = fwrite_unlocked(&li[i].discrim, len, 1, agent);
        if (sret != 1)
            goto error;

        sret = fwrite_unlocked(file_names[i], strlen(file_names[i]) + 1, 1, agent);
        if (sret != 1)
            goto error;
    }
    funlockfile(agent);
    return 0;
error:
    funlockfile(agent);
    return -1;
}

static jvmtiError
do_get_line_number(jvmtiEnv *jvmti, void *pc, jmethodID m, jint bci,
           jvmti_line_info_t *tab)
{
    jint i, nr_lines = 0;
    jvmtiLineNumberEntry *loc_tab = NULL;
    jvmtiError ret;
    jint src_line = -1;

    ret = jvmti->GetLineNumberTable(m, &nr_lines, &loc_tab);
    if (ret == JVMTI_ERROR_ABSENT_INFORMATION || ret == JVMTI_ERROR_NATIVE_METHOD) {
        /* No debug information for this method */
        return ret;
    } else if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetLineNumberTable %d", ret);
        return ret;
    }

    for (i = 0; i < nr_lines && loc_tab[i].start_location <= bci; i++) {
        src_line = i;
    }

    if (src_line != -1) {
        tab->pc = (unsigned long)pc;
        tab->line_number = loc_tab[src_line].line_number;
        tab->discrim = 0; /* not yet used */
        tab->methodID = m;

        ret = JVMTI_ERROR_NONE;
    } else {
        ret = JVMTI_ERROR_ABSENT_INFORMATION;
    }

    jvmti->Deallocate((unsigned char *)loc_tab);

    return ret;
}

static jvmtiError get_line_numbers(jvmtiEnv *jvmti, const void *compile_info, jvmti_line_info_t **tab, int *nr_lines)
{
    const jvmtiCompiledMethodLoadRecordHeader *hdr;
    jvmtiCompiledMethodLoadInlineRecord *rec;
    PCStackInfo *c;
    jint ret;
    int nr_total = 0;
    int i, lines_total = 0;

    if (!(tab && nr_lines))
        return JVMTI_ERROR_NULL_POINTER;

    /*
     * Phase 1 -- get the number of lines necessary
     */
    for (hdr = (const jvmtiCompiledMethodLoadRecordHeader *)compile_info; hdr != NULL; hdr = hdr->next) {
        if (hdr->kind == JVMTI_CMLR_INLINE_INFO) {
            rec = (jvmtiCompiledMethodLoadInlineRecord *)hdr;
            nr_total += rec->numpcs;
        }
    }

    if (nr_total == 0)
        return JVMTI_ERROR_NOT_FOUND;

    /*
     * Phase 2 -- allocate big enough line table
     */
    *tab = (jvmti_line_info_t *)os::malloc((size_t)(nr_total * sizeof(**tab)), mtLogging);
    if (!*tab)
        return JVMTI_ERROR_OUT_OF_MEMORY;

    for (hdr = (const jvmtiCompiledMethodLoadRecordHeader *)compile_info; hdr != NULL; hdr = hdr->next) {
        if (hdr->kind == JVMTI_CMLR_INLINE_INFO) {
            rec = (jvmtiCompiledMethodLoadInlineRecord *)hdr;
            for (i = 0; i < rec->numpcs; i++) {
                c = rec->pcinfo + i;
                                /*
                                 * c->methods is the stack of inlined method calls
                                 * at c->pc. [0] is the leaf method. Caller frames
                                 * are ignored at the moment.
                                 */
                ret = do_get_line_number(jvmti, c->pc,
                             c->methods[0],
                             c->bcis[0],
                             *tab + lines_total);
                if (ret == JVMTI_ERROR_NONE)
                    lines_total++;
            }
        }
    }
    *nr_lines = lines_total;
    return JVMTI_ERROR_NONE;
}

static void
copy_class_filename(const char * class_sign, const char * file_name, char * result, size_t max_length)
{
    /*
    * Assume path name is class hierarchy, this is a common practice with Java programs
    */
    if (*class_sign == 'L') {
        int i = 0;
        const char *p = strrchr(class_sign, '/');
        if (p) {
            /* drop the 'L' prefix and copy up to the final '/' */
            for (i = 0; i < (p - class_sign); i++)
                result[i] = class_sign[i+1];
        }
        /*
        * append file name, we use loops and not string ops to avoid modifying
        * class_sign which is used later for the symbol name
        */
        for (size_t j = 0; i < (int)(max_length - 1) && file_name && j < strlen(file_name); j++, i++)
            result[i] = file_name[j];

        result[i] = '\0';
    } else {
        /* fallback case */
        strncpy(result, file_name, max_length - 1);
    }
}

static jvmtiError get_source_filename(jvmtiEnv *jvmti, jmethodID methodID, char ** buffer)
{
    jvmtiError ret;
    jclass decl_class;
    char *file_name = NULL;
    char *class_sign = NULL;
    char fn[PATH_MAX];
    size_t len;

    ret = jvmti->GetMethodDeclaringClass(methodID, &decl_class);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetMethodDeclaringClass %d", ret);
        return ret;
    }

    ret = jvmti->GetSourceFileName(decl_class, &file_name);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetSourceFileName %d", ret);
        return ret;
    }

    ret = jvmti->GetClassSignature(decl_class, &class_sign, NULL);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetClassSignature %d", ret);
        goto free_file_name_error;
    }

    copy_class_filename(class_sign, file_name, fn, PATH_MAX);
    len = strlen(fn);
    *buffer = (char *)os::malloc((len + 1) * sizeof(char), mtLogging);
    if (!*buffer) {
        log_trace(dump)("GetClassSignature %d", ret);
        ret = JVMTI_ERROR_OUT_OF_MEMORY;
        goto free_class_sign_error;
    }
    strcpy(*buffer, fn);
    ret = JVMTI_ERROR_NONE;

free_class_sign_error:
    jvmti->Deallocate((unsigned char *)class_sign);
free_file_name_error:
    jvmti->Deallocate((unsigned char *)file_name);

    return ret;
}

static jvmtiError
fill_source_filenames(jvmtiEnv *jvmti, int nr_lines,
              const jvmti_line_info_t * line_tab,
              char ** file_names)
{
    int index;
    jvmtiError ret;

    for (index = 0; index < nr_lines; ++index) {
        ret = get_source_filename(jvmti, line_tab[index].methodID, &(file_names[index]));
        if (ret != JVMTI_ERROR_NONE)
            return ret;
    }

    return JVMTI_ERROR_NONE;
}

static void JNICALL compiled_method_load_cb(jvmtiEnv *jvmti,
            jmethodID method,
            jint code_size,
            void const *code_addr,
            jint map_length,
            jvmtiAddrLocationMap const *map,
            const void *compile_info)
{
    jvmti_line_info_t *line_tab = NULL;
    char ** line_file_names = NULL;
    jclass decl_class;
    char *class_sign = NULL;
    char *func_name = NULL;
    char *func_sign = NULL;
    uint64_t addr = (uint64_t)(uintptr_t)code_addr;
    int nr_lines = 0; /* in line_tab[] */
    size_t len;
    int output_debug_info = 0;

    jvmtiError ret = jvmti->GetMethodDeclaringClass(method, &decl_class);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetMethodDeclaringClass %d", ret);
        return;
    }

    if (has_line_numbers && map && map_length) {
        ret = get_line_numbers(jvmti, compile_info, &line_tab, &nr_lines);
        if (ret != JVMTI_ERROR_NONE) {
            if (ret != JVMTI_ERROR_NOT_FOUND) {
                log_trace(dump)("jvmti: cannot get line table for method");
            }
            nr_lines = 0;
        } else if (nr_lines > 0) {
            line_file_names = (char **)os::malloc(sizeof(char*) * nr_lines, mtLogging);
            if (!line_file_names) {
                log_trace(dump)("jvmti: cannot allocate space for line table method names");
            } else {
                memset(line_file_names, 0, sizeof(char*) * nr_lines);
                ret = fill_source_filenames(jvmti, nr_lines, line_tab, line_file_names);
                if (ret != JVMTI_ERROR_NONE) {
                    log_trace(dump)("jvmti: fill_source_filenames failed");
                } else {
                    output_debug_info = 1;
                }
            }
        }
    }

    ret = jvmti->GetClassSignature(decl_class, &class_sign, NULL);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetClassSignature %d", ret);
        goto error;
    }

    ret = jvmti->GetMethodName(method, &func_name, &func_sign, NULL);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetMethodName %d", ret);
        goto error;
    }

    /*
     * write source line info record if we have it
     */
    if (output_debug_info) {
        if (jvmti_write_debug_info(jvmti_agent, addr, nr_lines, line_tab, (const char * const *) line_file_names)) {
            log_trace(dump)("jvmti: write_debug_info() failed");
		}
	}

    len = strlen(func_name) + strlen(class_sign) + strlen(func_sign) + 2;
    {
        char str[len];
        snprintf(str, len, "%s%s%s", class_sign, func_name, func_sign);

        if (jvmti_write_code(jvmti_agent, str, code_addr, code_size)) {
            log_trace(dump)("jvmti: write_code() failed");
		}
    }
error:
    jvmti->Deallocate((unsigned char *)func_name);
    jvmti->Deallocate((unsigned char *)func_sign);
    jvmti->Deallocate((unsigned char *)class_sign);
    os::free(line_tab);
    while (line_file_names && (nr_lines > 0)) {
        if (line_file_names[nr_lines - 1]) {
            os::free(line_file_names[nr_lines - 1]);
        }
        nr_lines -= 1;
    }
    os::free(line_file_names);
}

static void JNICALL code_generated_cb(jvmtiEnv *jvmti, char const *name, void const *code_addr, jint code_size)
{
    int ret = jvmti_write_code(jvmti_agent, name, code_addr, code_size);
    if (ret) {
        log_trace(dump)("jvmti: write_code() failed for code_generated");
	}
}

bool PerfJitDumpAgent::open_marker_file(int fd)
{
    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz == -1)
        return false;

    /*
     * we mmap the jitdump to create an MMAP RECORD in perf.data file.
     * The mmap is captured either live (perf record running when we mmap)
     * or  in deferred mode, via /proc/PID/maps
     * the MMAP record is used as a marker of a jitdump file for more meta
     * data info about the jitted code. Perf report/annotate detect this
     * special filename and process the jitdump file.
     *
     * mapping must be PROT_EXEC to ensure it is captured by perf record
     * even when not using -d option
     */
    marker_addr = mmap(NULL, pgsz, PROT_READ|PROT_EXEC, MAP_PRIVATE, fd, 0);
    return (marker_addr == MAP_FAILED) ? false : true;
}

void PerfJitDumpAgent::close_marker_file()
{
    if (!marker_addr)
        return;

    long pgsz = sysconf(_SC_PAGESIZE);
    if (pgsz == -1)
        return;

    munmap(marker_addr, pgsz);
}

bool PerfJitDumpAgent::create()
{
    jvmtiEnv *jvmti = NULL;
    jint ret;

    jvmti_agent = jvmti_open();
    if (!jvmti_agent) {
        log_trace(dump)("jvmti: open_agent failed");
        return false;
    }

    /*
     * Request a JVMTI interface version 1 environment
     */
    extern struct JavaVM_ main_vm;
    JavaVM* vm = &main_vm;
    ret = vm->GetEnv((void **)&jvmti, JVMTI_VERSION_1);
    if (ret != JNI_OK) {
        log_trace(dump)("jvmti: jvmti version 1 not supported");
        return false;
    }

    /*
     * acquire method_load capability, we require it
     * request line numbers (optional)
     */
	jvmtiCapabilities caps1;
    memset(&caps1, 0, sizeof(caps1));
    caps1.can_generate_compiled_method_load_events = 1;

    ret = jvmti->AddCapabilities(&caps1);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("AddCapabilities %d", ret);
        return false;
    }

	jvmtiJlocationFormat format;
    ret = jvmti->GetJLocationFormat(&format);
    if (ret == JVMTI_ERROR_NONE && format == JVMTI_JLOCATION_JVMBCI) {
        memset(&caps1, 0, sizeof(caps1));
        caps1.can_get_line_numbers = 1;
        caps1.can_get_source_file_name = 1;
        ret = jvmti->AddCapabilities(&caps1);
        if (ret == JVMTI_ERROR_NONE) {
            has_line_numbers = true;
		}
    } else if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("GetJLocationFormat %d", ret);
	}

    jvmtiEventCallbacks cb;
    memset(&cb, 0, sizeof(cb));
    cb.CompiledMethodLoad   = compiled_method_load_cb;
    cb.DynamicCodeGenerated = code_generated_cb;

    ret = jvmti->SetEventCallbacks(&cb, sizeof(cb));
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("SetEventCallbacks %d", ret);
        return false;
    }

    ret = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_COMPILED_METHOD_LOAD, NULL);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("SetEventNotificationMode(METHOD_LOAD) %d", ret);
        return false;
    }

    ret = jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_DYNAMIC_CODE_GENERATED, NULL);
    if (ret != JVMTI_ERROR_NONE) {
        log_trace(dump)("SetEventNotificationMode(CODE_GENERATED) %d", ret);
        return false;
    }

    return true;
}

void PerfJitDumpAgent::close()
{
    if (jvmti_agent != nullptr) {
        struct jr_code_close rec;
        rec.p.id = JIT_CODE_CLOSE;
        rec.p.total_size = sizeof(rec);
        rec.p.timestamp = perf_get_timestamp();

        if (!fwrite(&rec, sizeof(rec), 1, jvmti_agent))
            log_trace(dump)("Error: cannot write close record");
        fclose(jvmti_agent);
        jvmti_agent = nullptr;

        PerfJitDumpAgent::close_marker_file();
    }
}