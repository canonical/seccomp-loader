#include "stdlib.h"

#include "seccomp.h"

int main(int argc, char **argv) {
	if (argc != 2) {
		sc_show_error_and_die("needs seccomp profile as first argument");
	}

	struct sock_fprog prog_allow = { .len = 0, .filter = NULL };
	struct sc_seccomp_file_header sc_hdr = { 0 };

	const char *profile_path = argv[1];
	FILE *sc_file  = sc_must_read_and_validate_header_from_file(profile_path, &sc_hdr);
    
	sc_must_read_filter_from_file(sc_file, sc_hdr.len_filter, &prog_allow);
	sc_apply_seccomp_filter(&prog_allow);

    if (prog_allow.filter != NULL) {
        free(prog_allow.filter);
    }

    if (sc_file) {
        fclose(sc_file);
    }

    fprintf(stderr, "filter loader okay");
    return 0;
}
