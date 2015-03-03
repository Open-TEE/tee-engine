LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  libManagerApi
LOCAL_SRC_FILES	    :=   \
	ext_storage_stream_api_posix.c \
	opentee_manager_storage_api.c \
	io_thread.c \
	logic_thread.c \
	mainloop.c \
	ta_dir_watch.c \
	shm_mem.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    :=  \
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/../internal_api \
			$(LOCAL_PATH)/../include \
			$(LOCAL_PATH)/../common \
			external/elfutils/0.153/libelf 

LOCAL_SHARED_LIBRARIES := libc libdl libCommonApi 
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_SHARED_LIBRARY)

