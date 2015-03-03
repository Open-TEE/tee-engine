LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libLauncherApi

LOCAL_SRC_FILES := \
		    dynamic_loader.c		\
		    launcher_mainloop.c		\
		    ta_internal_thread.c	\
		    ta_io_thread.c		\
		    ta_process.c 		\
		    ta_signal_handler.c

LOCAL_C_INCLUDES    :=	\
			$(LOCAL_PATH) \
			$(LOCAL_PATH)/../include \
			$(LOCAL_PATH)/../common \
			$(LOCAL_PATH)/../internal_api
			

LOCAL_SHARED_LIBRARIES := libc libdl libCommonApi libInternalApi

LOCAL_EXPORT_C_INCLUDE_DIRS :=	\

local_c_flags := -DANDROID

include $(BUILD_SHARED_LIBRARY)