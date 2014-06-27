AM_CPPFLAGS = -I../include -I../internal_api/
lib_LTLIBRARIES = libManagerApi.la
libManagerApi_la_LIBADD = -lelf ../common/libCommonApi.la
libManagerApi_la_SOURCES = mainloop.c epoll_wrapper.c process_manager.c
METASOURCES = AUTO
