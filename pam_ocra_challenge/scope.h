#ifndef OCRA_SCOPE_H
#define OCRA_SCOPE_H

#include <sys/types.h>

#define OCRA_SERVICE_MAX_LENGTH 64U
#define OCRA_UID_TEXT_MAX_LENGTH 10U

int ocra_scope_parse_uid(const char *text, uid_t *uid);
int ocra_scope_validate_service(const char *service);

#endif
