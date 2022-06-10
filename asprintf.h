#ifndef NCAP_ASPRINTF_H

/*! \file nmsg/asprintf.h
 * \brief Asprintf utility functions.
 *
 * Portable replacements for the asprintf(3) and vasprintf(3) functions.
 */

#include <stdarg.h>

int ncap_asprintf(char **strp, const char *fmt, ...);
int ncap_vasprintf(char **strp, const char *fmt, va_list args);

#endif /* NCAP_ASPRINTF_H */
