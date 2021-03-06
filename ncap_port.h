#ifndef NCAP_PORT_H
#define NCAP_PORT_H

#include "config.h"

#ifdef __linux__
# define _GNU_SOURCE
# include <features.h>
# define __FAVOR_BSD
#endif

#ifdef __hpux
# define __BIT_TYPES_DEFINED
# define __HPLX
#endif

#ifndef alloca
# ifdef HAVE_ALLOCA_H
#  include <alloca.h>
# elif defined __GNUC__
#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# else
#  include <stddef.h>
void *alloca (size_t);
# endif
#endif

#ifdef HAVE_STDBOOL_H
# include <stdbool.h>
#else
# ifndef HAVE__BOOL
#  ifdef __cplusplus
typedef bool _Bool;
#  else
#   define _Bool signed char
#  endif
# endif
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

#ifdef NEED_ASPRINTF_DECL
#include <stdarg.h>
int asprintf(char **ret, const char *format, ...);
#endif

#undef __attribute__
#if __GNUC__ >= 3 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 95)
# define __attribute__(x)	__attribute__(x)
#else
# define __attribute__(x)
#endif

#if (FLEXIBLE_ARRAY_MEMBER+1) == 1
# define ZERO_LENGTH_ARRAY
#else
# define ZERO_LENGTH_ARRAY	0
#endif

#endif
