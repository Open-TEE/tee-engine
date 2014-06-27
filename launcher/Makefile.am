AM_CPPFLAGS = -I../include
lib_LTLIBRARIES = libLauncherApi.la
libLauncherApi_la_LDFLAGS = $(all_libraries) -ldl
libLauncherApi_la_LIBADD = ../common/libCommonApi.la ../internal_api/libInternalApi.la
libLauncherApi_la_SOURCES = launcher_mainloop.c dynamic_loader.c ta_process.c
METASOURCES = AUTO
