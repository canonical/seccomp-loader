#ifndef SC_SECCOMP_H
#define SC_SECCOMP_H

#include <stdio.h>
#include <stdint.h>
#include <linux/filter.h>

/* Expected header values */
#define SC_SECCOMP_HEADER_MAGIC0  'S'
#define SC_SECCOMP_HEADER_MAGIC1  'C'
#define SC_SECCOMP_HEADER_VERSION 1

/* Largest filter the kernel accepts: BPF_MAXINSNS (4096) instructions of 8 bytes */
#define SC_MAX_BPF_SIZE (BPF_MAXINSNS * sizeof(struct sock_filter))

/*
 * On-disk header of a seccomp profile file, read as-is with fread().
 * All fields are in host byte order.
 */
struct sc_seccomp_file_header {
    char header[2];          // must be 'S', 'C'
    uint8_t version;         // must be SC_SECCOMP_HEADER_VERSION
    uint8_t unrestricted;    // must be 0 or 1
    uint32_t len_filter;     // filter size in bytes, multiple of sizeof(struct sock_filter)
    uint8_t reserved2[16];   // reserved for future use
};

/* The on-disk format is 24 bytes; catch any accidental layout change */
_Static_assert(sizeof(struct sc_seccomp_file_header) == 24,
               "unexpected sc_seccomp_file_header size");

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog);

FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr);

void sc_apply_seccomp_filter(struct sock_fprog *prog);

void die(const char *fmt, ...);

#endif // SC_SECCOMP_H
