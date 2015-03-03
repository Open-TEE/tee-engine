LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

local_src_files	    :=                          \
		    dynamic_loader.c		\
		    launcher_mainloop.c		\
		    ta_internal_thread.c	\
		    ta_io_thread.c		\
		    ta_process.c

local_c_includes    :=				\
		    dynamic_loader.h		\
		    ta_internal_thread.h	\
		    ta_io_thread.h		\
		    ta_process.h


local_export_c_include_dirs :=			/


local_c_flags := -DANDROID

#################################################
# Target dynamic library

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(local_src_files)
LOCAL_C_INCLUDES += $(local_c_includes)
LOCAL_CFLAGS += $(local_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(local_export_c_include_dirs)
LOCAL_SHARED_LIBRARIES += libc libdl
LOCAL_MODULE := LauncherApi
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := LauncherApi
LOCAL_COPY_HEADERS += \
	       $(LOCAL_PATH)/../include/core_control_resources.h    \
	       $(LOCAL_PATH)/../include/ta_exit_states.h	    \
	       $(LOCAL_PATH)/../internal_api/callbacks.h	    \
	       ta_extern_resources.h
include $(BUILD_SHARED_LIBRARY)

###############################################
