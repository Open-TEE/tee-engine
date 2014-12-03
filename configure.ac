#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([opentee-core], [0.0.0], [https://github.com/Open-TEE/tee-engine/issues],
	[opentee-core], [https://github.com/Open-TEE])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([internal_api/tee_time_api.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
LT_INIT

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([ssl], [OPENSSL_malloc])
AC_CHECK_LIB([dl], [dlopen])
AC_CHECK_LIB([libelf], [elf_version])

# Created configuration files.
AC_CONFIG_FILES([Makefile])

AC_OUTPUT
