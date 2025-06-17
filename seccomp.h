#ifndef X_SECCOMP_H
#define X_SUPPORT_H

#define MAX_BPF_SIZE (32*1024)

#include <stdio.h>
#include <stdint.h>
#include <linux/filter.h>

/* Seccomp profile file header structure */
struct sc_seccomp_file_header {
	char header[2];        /* Must be "SC" */
	uint8_t version;       /* Must be 0x1 */
	uint8_t unrestricted;  /* Must be 0x0 or 0x1 */
	uint32_t len_filter;   /* Must be multiple of sizeof(struct sock_filter) */
	uint8_t reserved2[16]; /* Must be zeroed */
};

/* Error codes for seccomp operations */
#define SC_SUCCESS 0
#define SC_ERROR_INVALID_VERSION -1
#define SC_ERROR_INVALID_UNRESTRICTED -2
#define SC_ERROR_INVALID_RESERVED -3
#define SC_ERROR_INVALID_FILTER_LEN -4
#define SC_ERROR_FILE_OPEN -5
#define SC_ERROR_FILE_READ -6
#define SC_ERROR_SHORT_READ -7

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog);
int sc_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr, FILE **file_out);
void sc_apply_seccomp_filter(struct sock_fprog *prog);
void die(const char *fmt, ...);

#endif
