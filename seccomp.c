#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/filter.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>

#include "seccomp.h"

void die(const char *msg, ...)
{
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

/* Shared size checks, used when reading the header and again before reading the filter */
static void sc_must_validate_filter_len(uint32_t len_bytes)
{
    if (len_bytes == 0) {
        die("seccomp filter is empty");
    }
    if (len_bytes > SC_MAX_BPF_SIZE) {
        die("seccomp filter size too big: %u (max %zu)", len_bytes, (size_t)SC_MAX_BPF_SIZE);
    }
    if (len_bytes % sizeof(struct sock_filter) != 0) {
        die("seccomp filter size %u is not a multiple of %zu", len_bytes, sizeof(struct sock_filter));
    }
}

FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr)
{
    // "e" = O_CLOEXEC, so the fd is not inherited by programs exec'd later
    FILE *file = fopen(profile_path, "rbe");
    if (file == NULL) {
        die("cannot open seccomp filter %s: %s", profile_path, strerror(errno));
    }

    // The profile decides what the process may do, so it must be a regular
    // file that only its owner can modify
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        die("cannot stat seccomp profile %s: %s", profile_path, strerror(errno));
    }
    if (!S_ISREG(st.st_mode)) {
        die("seccomp profile %s is not a regular file", profile_path);
    }
    if (st.st_mode & (S_IWGRP | S_IWOTH)) {
        die("seccomp profile %s is writable by group or others", profile_path);
    }

    size_t num_read = fread(hdr, 1, sizeof(struct sc_seccomp_file_header), file);
    if (ferror(file) != 0) {
        die("cannot read seccomp profile %s", profile_path);
    }
    if (num_read < sizeof(struct sc_seccomp_file_header)) {
        die("short read on seccomp header: %zu", num_read);
    }

    if (hdr->header[0] != SC_SECCOMP_HEADER_MAGIC0 || hdr->header[1] != SC_SECCOMP_HEADER_MAGIC1) {
        die("unexpected seccomp header: %02x%02x",
            (unsigned char)hdr->header[0], (unsigned char)hdr->header[1]);
    }
    if (hdr->version != SC_SECCOMP_HEADER_VERSION) {
        die("unsupported seccomp header version: %u", hdr->version);
    }
    if (hdr->unrestricted > 1) {
        die("invalid unrestricted value in seccomp header: %u", hdr->unrestricted);
    }
    sc_must_validate_filter_len(hdr->len_filter);

    return file;
}

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog)
{
    // Don't rely on the caller having validated the size
    sc_must_validate_filter_len(len_bytes);

    // Allocate exactly what will be read (the old code allocated a fixed
    // 32 KiB and read len_bytes into it, overflowing for larger values)
    prog->filter = (struct sock_filter *)malloc(len_bytes);
    if (prog->filter == NULL) {
        die("cannot allocate %u bytes of memory for seccomp filter", len_bytes);
    }
    // len_bytes <= SC_MAX_BPF_SIZE, so this fits in unsigned short
    prog->len = (unsigned short)(len_bytes / sizeof(struct sock_filter));

    size_t num_read = fread(prog->filter, 1, len_bytes, file);
    if (ferror(file)) {
        die("cannot read filter");
    }
    if (num_read != len_bytes) {
        die("short read for filter %zu != %u", num_read, len_bytes);
    }

    // Anything after the filter means the file is corrupt or not what the header says
    if (fgetc(file) != EOF) {
        die("unexpected data after seccomp filter");
    }
}

int seccomp(unsigned int operation, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, operation, flags, args);
}

void sc_apply_seccomp_filter(struct sock_fprog *prog) {
    // Required to load a filter without CAP_SYS_ADMIN
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        die("cannot set no_new_privs: %s", strerror(errno));
    }

    int err = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, prog);
    if (err != 0) {
        die("cannot apply seccomp profile: %s", strerror(errno));
    }
}
