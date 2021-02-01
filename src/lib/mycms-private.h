#ifndef __MYCMS_PRIVATE_H
#define __MYCMS_PRIVATE_H

#include <mycms/mycms.h>

void *
_mycms_get_pkcs11_state(
	const mycms mycms
);

int
_mycms_set_pkcs11_state(
	const mycms mycms,
	void *pkcs11_state
);

#endif
