LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE        :=  opentee-engine
LOCAL_SRC_FILES	    :=   \
		    args.c                  \
		    conf_parser.c           \
		    ini.c                   \
		    main.c

LOCAL_C_FLAGS       :=  -rdynamic -DANDROID

LOCAL_C_INCLUDES    :=  \
		    $(LOCAL_PATH)/../include/

LOCAL_SHARED_LIBRARIES := libdl
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include

include $(BUILD_EXECUTABLE)