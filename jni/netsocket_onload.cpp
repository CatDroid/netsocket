#include <jni.h>

#define LOG_TAG "jni_netsocket"
#include "vortex.h"




extern jboolean register_jni_netsocket_ping(JavaVM* vm, JNIEnv* env);
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{

    JNIEnv* env ;
    if ( vm->GetEnv( (void**) &env, JNI_VERSION_1_6 )  != JNI_OK) {
    	ALOGE("GetEnv Err");
    	return JNI_ERR;
    }

    register_jni_netsocket_ping(vm, env);



	return JNI_VERSION_1_6 ;
}

