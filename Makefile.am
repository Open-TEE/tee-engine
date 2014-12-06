## Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -D _GNU_SOURCE

# Executables
bin_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# Include module-specific Makefiles
include core/Makemodule.am
include common/Makemodule.am
include manager/Makemodule.am
include launcher/Makemodule.am
include internal_api/Makemodule.am
