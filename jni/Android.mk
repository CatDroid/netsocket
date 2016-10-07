LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := netsocket
LOCAL_SRC_FILES := netsocket_onload.cpp jni_netsocket_ping.cpp NativeContext.cpp vortex.cpp
LOCAL_LDLIBS    := -llog -landroid -lmediandk
LOCAL_CFLAGS	+= -Wall

include $(BUILD_SHARED_LIBRARY)
