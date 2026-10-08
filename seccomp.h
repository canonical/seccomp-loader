#ifndef X_SECCOMP_H
#define X_SUPPORT_H


#include <stdio.h>
#include <stdint.h>

#include <linux/filter.h>

struct sc_seccomp_file_header {
	char header[2]; //even with the added comment, number 2 are still a magic number, the 
					//comment doesn't describe what 2 are other than saying that it is must 
					//be S or C which can create a confusion in the future regarding what 2 
					//is when S and C changed or added. We could  define the number in 
					//preprocessing like #define HEADER_STATUS 2 and use it like header[HEADER_STATUS ]
	uint8_t version;
	uint8_t unrestricted;

	uint32_t len_filter;
	uint8_t reserved2[16]; //number 16 are a magic number which can create a confusion in the future 
							//regarding what 16 is. We could  define the number in preprocessing like 
							//#define HEADER_SIZE 16 and use it like reserved2[HEADER_SIZE]. Also 
							//there may be confusion on why this variable is named reserved2, it may 
							//need a comment pointing what it is reserving to make clear distinction on reserved1.
};

void sc_must_read_filter_from_file(FILE *file, uint32_t len_bytes, struct sock_fprog *prog);
FILE* sc_must_read_and_validate_header_from_file(const char *profile_path, struct sc_seccomp_file_header *hdr);
void sc_apply_seccomp_filter(struct sock_fprog *prog);

void die(const char *fmt, ...); //this function doesnt put a size or data type limit on its parameter, 
								//this could be a risk especially when it is accidentally called to process user input, 
								//this risk could cause errors, memory leak, or even security risk. We could declare a 
								//function that accept a fixed string parameter with a fixed size to prevent the problem, 
								//this will also made sure that any error massage should be clear and consise.

#endif
