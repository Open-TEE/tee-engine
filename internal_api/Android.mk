LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  libInternalApi
LOCAL_SRC_FILES	    := \
	callbacks.c \
	openssl_1_0_2_beta_rsa_oaep.c \
	tee_bigint.c \
	tee_cancellation.c \
	tee_crypto_api.c \
	tee_internal_client_api.c \
	tee_memory.c \
	tee_panic.c \
	opentee_storage_common.c \
	opentee_internal_api.c \
	tee_storage_api.c \
	tee_time_api.c

LOCAL_C_INCLUDES    :=  \
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/../include \
			$(LOCAL_PATH)/../internal_api \
			external/openssl/include

LOCAL_CFLAGS       := -rdynamic -DANDROID -DOT_LOGGING

LOCAL_SHARED_LIBRARIES := libssl libcrypto libc

LOCAL_EXPORT_C_INCLUDE_DIRS :=	\
				$(LOCAL_PATH)/../include \
				$(LOCAL_PATH)/../internal_api

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_SHARED_LIBRARY)
