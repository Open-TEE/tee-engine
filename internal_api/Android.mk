LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  internal-api
LOCAL_SRC_FILES	    :=  tee_time_api.c tee_storage_api.c tee_panic.c \
						tee_memory.c  tee_internal_client_api.c tee_crypto_api.c \
						tee_cancellation.c tee_bigint.c opentee_storage_common.c \
						opentee_internal_api.c openssl_1_0_2_beta_rsa_oaep.c callbacks.c 


LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    :=  $(LOCAL_PATH)/ \
		    $(LOCAL_PATH)/../include/

LOCAL_STATIC_LIBRARIES := libopenssl-static
#LOCAL_SHARED_LIBRARIES := libdl
#LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_SHARED_LIBRARY)
