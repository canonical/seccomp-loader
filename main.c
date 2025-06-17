#include "seccomp.h"

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <seccomp-profile>\n", argv[0]);
		fprintf(stderr, "Load and apply a seccomp filter from the specified profile file.\n");
		exit(1);
	}

	struct sock_fprog  prog_allow = { 0 };
	struct sc_seccomp_file_header hdr = {0};

	const char *profile_path = argv[1];
	FILE *file  = sc_must_read_and_validate_header_from_file(profile_path, &hdr);
	sc_must_read_filter_from_file(file, hdr.len_filter, &prog_allow);

	sc_apply_seccomp_filter(&prog_allow);
	fprintf(stdout, "Successfully loaded seccomp filter from %s\n", profile_path);
}
