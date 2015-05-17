## Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Additional C compiler flags
AM_CFLAGS = -Wall -Wextra -DOT_LOGGING -D_FORTIFY_SOURCE=2

# Executables
bin_PROGRAMS =

# Shared libraries
lib_LTLIBRARIES  =

# Include module-specific Makefiles
include opentee-main/Makemodule.am
include common/Makemodule.am
include manager/Makemodule.am
include internal_api/Makemodule.am
include launcher/Makemodule.am
