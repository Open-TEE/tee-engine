LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

local_src_files	    :=                          \
		    com_protocol.c		\
		    elf_read.c			\
		    epoll_wrapper.c		\
		    socket_help.c		\
		    tee_list.c

local_c_includes    :=				\
		    $(LOCAL_PATH)/../include/

local_export_c_include_dirs := /

local_c_flags := -DANDROID

#################################################
# Target dynamic library

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(local_src_files)
LOCAL_C_INCLUDES += $(local_c_includes) external/zlib external/elfutils/0.153/libelf
LOCAL_STATIC_LIBRARIES += 
LOCAL_CFLAGS += $(local_c_flags)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(local_export_c_include_dirs)
LOCAL_SHARED_LIBRARIES += libz
LOCAL_STATIC_LIBRARIES += libelf
LOCAL_MODULE := CommonApi
LOCAL_MODULE_TAGS := optional
LOCAL_COPY_HEADERS_TO := CommonApi
LOCAL_COPY_HEADERS += \

include $(BUILD_SHARED_LIBRARY)

###############################################
