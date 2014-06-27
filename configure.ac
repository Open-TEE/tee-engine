#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([Open-TEE], [1.0], [open-tee@googlegroups.com])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([main/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS

# Checks for libraries.
LT_INIT
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-ldl':
AC_CHECK_LIB([dl], [main])
AC_CHECK_LIB([ssl], [RSA_new])
AC_CHECK_LIB([elf], [read_metadata])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ftruncate gettimeofday memchr memmove memset mkdir rmdir select socket strerror strstr])

AC_CONFIG_FILES([Makefile
                 common/Makefile
                 internal_api/Makefile
                 launcher/Makefile
                 manager/Makefile
                 main/Makefile
				 TAs/Makefile
				 TAs/test_applet/Makefile
				 tests/Makefile])
AC_OUTPUT
