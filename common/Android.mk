LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libCommonApi

LOCAL_SRC_FILES	    :=                          \
		    com_protocol.c		\
		    elf_read.c			\
		    epoll_wrapper.c		\
		    tee_list.c

LOCAL_C_INCLUDES += \
			$(LOCAL_PATH)/../include \
			external/zlib \
			external/elfutils/0.153/libelf \
			external/elfutils/src/libelf

LOCAL_EXPORT_C_INCLUDE_DIRS :=  $(LOCAL_PATH)/../include/

LOCAL_CFLAGS := -DANDROID -DOT_LOGGING

LOCAL_SHARED_LIBRARIES := libz libc
LOCAL_STATIC_LIBRARIES := libelf

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_SHARED_LIBRARY)
