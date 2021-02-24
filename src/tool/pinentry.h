#ifndef __PINENTRY_H
#define __PINENTRY_H

int
pinentry_exec(
	const char * const prog,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
);

#endif
