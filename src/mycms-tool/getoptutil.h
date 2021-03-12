#ifndef __GETOPTUTIL_H
#define __GETOPTUTIL_H

/**
 * @file
 * @brief getopt_long utilities.
 */


#include <getopt.h>
#include <stdio.h>

/**
 * Construct usage out of options.
 * @param out output file.
 * @param argv0 program file.
 * @param extra_usage some additional notes.
 * @param options the options, description is after null character.
 */
void
getoptutil_usage(
	FILE *out,
	const char * const argv0,
	const char * const extra_usage,
	const struct option * const options
);

/**
 * Construct short options out of long options.
 * @param options the options.
 * @param optstring the output short options.
 * @param optstring_size the output size.
 * @return 0 if buffer too short.
 */
int
getoptutil_short_from_long(
	const struct option * const options,
	const char * const prefix,
	char * const optstring,
	size_t optstring_size
);

#endif
