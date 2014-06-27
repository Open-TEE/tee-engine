AM_CPPFLAGS = -I../include
lib_LTLIBRARIES = libInternalApi.la
libInternalApi_la_LDFLAGS = $(all_libraries)
libInternalApi_la_SOURCES = tee_memory.c time_api.c tee_storage_api.c storage_key_apis_external_funcs.c tee_panic.c tee_crypto_api.c openssl_1_0_2_beta_rsa_oaep.c
libInternalApi_la_LIBADD = -lssl -lcrypto
METASOURCES = AUTO
