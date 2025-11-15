#ifndef X_SECCOMP_H
#define X_SECCOMP_H

#include <stdio.h>
#include <stdint.h>

#include <linux/filter.h>

struct sc_seccomp_file_header {
    /// @brief Header bytes, expected to be 'S', 'C'.
	char header[2];

    /// @brief Version of "seccomp", only 0x1 supported.
	uint8_t version;

    /// @brief The unrestricted byte, only 0x0 or 0x1 supported right now.
	uint8_t unrestricted;

    /// @brief The filter length expected, cannot exceed 32768.
	uint32_t len_filter;

    /// @brief Reserved bytes for header (do not remove).
	uint8_t reserved2[16];
};

/**
 * @brief Reads the "seccomp" filter from a file.
 * @param file              File to read from.
 * @param len_filter        Filter length.
 * @param prog              Program to update.
 */
void sc_must_read_filter_from_file(FILE *file, uint32_t len_filter, struct sock_fprog *prog);

/**
 * @brief Reads and validates a "seccomp" file header.
 * @param profile_path      Profile path.
 * @param hdr               Header pointer.
 * @return                  The file if valid, NULL otherwise.
 */
FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr);

/**
 * @brief Applies the "seccomp" filter to given program.
 * @param prog              Program to apply filter to.
 */
void sc_apply_seccomp_filter(struct sock_fprog *prog);

/**
 * @brief Shows formatted "seccomp" errors and then exits the process with exit-code 1.
 * @param fmt               Error format.
 * @param ...               Variadic arguments.
 */
void sc_show_error_and_die(const char *fmt, ...);

#endif
