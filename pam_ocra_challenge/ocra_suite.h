#ifndef OCRA_SUITE_H
#define OCRA_SUITE_H

#include <stddef.h>

#define OCRA_SUITE "OCRA-1:HOTP-SHA256-8:QN10"
#define OCRA_SUITE_LENGTH 25U
#define OCRA_QUESTION_BYTES 128U
#define OCRA_DATA_INPUT_BYTES 154U

int ocra_suite_build_data_input(const char *challenge, size_t challenge_length,
                                unsigned char *output, size_t output_size);

#endif
