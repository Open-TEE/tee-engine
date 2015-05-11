LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  opentee-engine
LOCAL_SRC_FILES	    :=   \
		    args.c                  \
		    conf_parser.c           \
		    ini.c                   \
		    main.c

LOCAL_CFLAGS       :=  -rdynamic -DANDROID -DOT_LOGGING

LOCAL_C_INCLUDES    :=  \
		    $(LOCAL_PATH)/../include \
		    $(LOCAL_PATH)/../common

LOCAL_SHARED_LIBRARIES := libdl
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

ifeq ($(TARGET_ARCH),arm)
LOCAL_LDFLAGS := -Wl,--hash-style=sysv
endif

include $(BUILD_EXECUTABLE)
