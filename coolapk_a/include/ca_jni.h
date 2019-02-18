/* DO NOT EDIT This file: generated by dwarf_to_c from coolapk liba.so DWARF Debug information */
#pragma once

#include <stdarg.h>

/* Basetype: unsigned char */
typedef unsigned char jboolean;
/* Basetype: signed char */
typedef signed char jbyte;
/* Basetype: short unsigned int */
typedef short unsigned int jchar;
/* Basetype: short int */
typedef short int jshort;
/* Basetype: int */
typedef int jint;
/* Basetype: long long int */
typedef long long int jlong;
/* Basetype: float */
typedef float jfloat;
/* Basetype: double */
typedef double jdouble;
typedef jint jsize;
typedef void *jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef jarray jbooleanArray;
typedef jarray jbyteArray;
typedef jarray jcharArray;
typedef jarray jshortArray;
typedef jarray jintArray;
typedef jarray jlongArray;
typedef jarray jfloatArray;
typedef jarray jdoubleArray;
typedef jobject jthrowable;
typedef jobject jweak;
typedef struct _jfieldID *jfieldID;
struct _jfieldID;
typedef struct _jmethodID *jmethodID;
struct _jmethodID;
union jvalue
{
    jboolean z;
    jbyte b;
    jchar c;
    jshort s;
    jint i;
    jlong j;
    jfloat f;
    jdouble d;
    jobject l;
};
typedef union jvalue jvalue;
enum jobjectRefType {
    JNIInvalidRefType = 0, /* 0x00000000 */
    JNILocalRefType = 1, /* 0x00000001 */
    JNIGlobalRefType = 2, /* 0x00000002 */
    JNIWeakGlobalRefType = 3 /* 0x00000003 */
};
typedef enum jobjectRefType jobjectRefType;
typedef struct
{
    char *name; /* +0x0 */
    char *signature; /* +0x4 */
    void *fnPtr; /* +0x8 */
} JNINativeMethod;
typedef struct JNINativeInterface *JNIEnv;
typedef struct JNIInvokeInterface *JavaVM;
struct JNINativeInterface
{
    void *reserved0; /* +0x0 */
    void *reserved1; /* +0x4 */
    void *reserved2; /* +0x8 */
    void *reserved3; /* +0xc */
    jint (*GetVersion)(JNIEnv *); /* +0x10 */
    jclass (*DefineClass)(JNIEnv *, char *, jobject, jbyte *, jsize); /* +0x14 */
    jclass (*FindClass)(JNIEnv *, char *); /* +0x18 */
    jmethodID (*FromReflectedMethod)(JNIEnv *, jobject); /* +0x1c */
    jfieldID (*FromReflectedField)(JNIEnv *, jobject); /* +0x20 */
    jobject (*ToReflectedMethod)(JNIEnv *, jclass, jmethodID, jboolean); /* +0x24 */
    jclass (*GetSuperclass)(JNIEnv *, jclass); /* +0x28 */
    jboolean (*IsAssignableFrom)(JNIEnv *, jclass, jclass); /* +0x2c */
    jobject (*ToReflectedField)(JNIEnv *, jclass, jfieldID, jboolean); /* +0x30 */
    jint (*Throw)(JNIEnv *, jthrowable); /* +0x34 */
    jint (*ThrowNew)(JNIEnv *, jclass, char *); /* +0x38 */
    jthrowable (*ExceptionOccurred)(JNIEnv *); /* +0x3c */
    void (*ExceptionDescribe)(JNIEnv *); /* +0x40 */
    void (*ExceptionClear)(JNIEnv *); /* +0x44 */
    void (*FatalError)(JNIEnv *, char *); /* +0x48 */
    jint (*PushLocalFrame)(JNIEnv *, jint); /* +0x4c */
    jobject (*PopLocalFrame)(JNIEnv *, jobject); /* +0x50 */
    jobject (*NewGlobalRef)(JNIEnv *, jobject); /* +0x54 */
    void (*DeleteGlobalRef)(JNIEnv *, jobject); /* +0x58 */
    void (*DeleteLocalRef)(JNIEnv *, jobject); /* +0x5c */
    jboolean (*IsSameObject)(JNIEnv *, jobject, jobject); /* +0x60 */
    jobject (*NewLocalRef)(JNIEnv *, jobject); /* +0x64 */
    jint (*EnsureLocalCapacity)(JNIEnv *, jint); /* +0x68 */
    jobject (*AllocObject)(JNIEnv *, jclass); /* +0x6c */
    jobject (*NewObject)(JNIEnv *, jclass, jmethodID); /* +0x70 */
    jobject (*NewObjectV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x74 */
    jobject (*NewObjectA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x78 */
    jclass (*GetObjectClass)(JNIEnv *, jobject); /* +0x7c */
    jboolean (*IsInstanceOf)(JNIEnv *, jobject, jclass); /* +0x80 */
    jmethodID (*GetMethodID)(JNIEnv *, jclass, char *, char *); /* +0x84 */
    jobject (*CallObjectMethod)(JNIEnv *, jobject, jmethodID); /* +0x88 */
    jobject (*CallObjectMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0x8c */
    jobject (*CallObjectMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0x90 */
    jboolean (*CallBooleanMethod)(JNIEnv *, jobject, jmethodID); /* +0x94 */
    jboolean (*CallBooleanMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0x98 */
    jboolean (*CallBooleanMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0x9c */
    jbyte (*CallByteMethod)(JNIEnv *, jobject, jmethodID); /* +0xa0 */
    jbyte (*CallByteMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xa4 */
    jbyte (*CallByteMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xa8 */
    jchar (*CallCharMethod)(JNIEnv *, jobject, jmethodID); /* +0xac */
    jchar (*CallCharMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xb0 */
    jchar (*CallCharMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xb4 */
    jshort (*CallShortMethod)(JNIEnv *, jobject, jmethodID); /* +0xb8 */
    jshort (*CallShortMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xbc */
    jshort (*CallShortMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xc0 */
    jint (*CallIntMethod)(JNIEnv *, jobject, jmethodID); /* +0xc4 */
    jint (*CallIntMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xc8 */
    jint (*CallIntMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xcc */
    jlong (*CallLongMethod)(JNIEnv *, jobject, jmethodID); /* +0xd0 */
    jlong (*CallLongMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xd4 */
    jlong (*CallLongMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xd8 */
    jfloat (*CallFloatMethod)(JNIEnv *, jobject, jmethodID); /* +0xdc */
    jfloat (*CallFloatMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xe0 */
    jfloat (*CallFloatMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xe4 */
    jdouble (*CallDoubleMethod)(JNIEnv *, jobject, jmethodID); /* +0xe8 */
    jdouble (*CallDoubleMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xec */
    jdouble (*CallDoubleMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xf0 */
    void (*CallVoidMethod)(JNIEnv *, jobject, jmethodID); /* +0xf4 */
    void (*CallVoidMethodV)(JNIEnv *, jobject, jmethodID, va_list); /* +0xf8 */
    void (*CallVoidMethodA)(JNIEnv *, jobject, jmethodID, jvalue *); /* +0xfc */
    jobject (*CallNonvirtualObjectMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x100 */
    jobject (*CallNonvirtualObjectMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x104 */
    jobject (*CallNonvirtualObjectMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x108 */
    jboolean (*CallNonvirtualBooleanMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x10c */
    jboolean (*CallNonvirtualBooleanMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x110 */
    jboolean (*CallNonvirtualBooleanMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x114 */
    jbyte (*CallNonvirtualByteMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x118 */
    jbyte (*CallNonvirtualByteMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x11c */
    jbyte (*CallNonvirtualByteMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x120 */
    jchar (*CallNonvirtualCharMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x124 */
    jchar (*CallNonvirtualCharMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x128 */
    jchar (*CallNonvirtualCharMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x12c */
    jshort (*CallNonvirtualShortMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x130 */
    jshort (*CallNonvirtualShortMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x134 */
    jshort (*CallNonvirtualShortMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x138 */
    jint (*CallNonvirtualIntMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x13c */
    jint (*CallNonvirtualIntMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x140 */
    jint (*CallNonvirtualIntMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x144 */
    jlong (*CallNonvirtualLongMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x148 */
    jlong (*CallNonvirtualLongMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x14c */
    jlong (*CallNonvirtualLongMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x150 */
    jfloat (*CallNonvirtualFloatMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x154 */
    jfloat (*CallNonvirtualFloatMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x158 */
    jfloat (*CallNonvirtualFloatMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x15c */
    jdouble (*CallNonvirtualDoubleMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x160 */
    jdouble (*CallNonvirtualDoubleMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x164 */
    jdouble (*CallNonvirtualDoubleMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x168 */
    void (*CallNonvirtualVoidMethod)(JNIEnv *, jobject, jclass, jmethodID); /* +0x16c */
    void (*CallNonvirtualVoidMethodV)(JNIEnv *, jobject, jclass, jmethodID, va_list); /* +0x170 */
    void (*CallNonvirtualVoidMethodA)(JNIEnv *, jobject, jclass, jmethodID, jvalue *); /* +0x174 */
    jfieldID (*GetFieldID)(JNIEnv *, jclass, char *, char *); /* +0x178 */
    jobject (*GetObjectField)(JNIEnv *, jobject, jfieldID); /* +0x17c */
    jboolean (*GetBooleanField)(JNIEnv *, jobject, jfieldID); /* +0x180 */
    jbyte (*GetByteField)(JNIEnv *, jobject, jfieldID); /* +0x184 */
    jchar (*GetCharField)(JNIEnv *, jobject, jfieldID); /* +0x188 */
    jshort (*GetShortField)(JNIEnv *, jobject, jfieldID); /* +0x18c */
    jint (*GetIntField)(JNIEnv *, jobject, jfieldID); /* +0x190 */
    jlong (*GetLongField)(JNIEnv *, jobject, jfieldID); /* +0x194 */
    jfloat (*GetFloatField)(JNIEnv *, jobject, jfieldID); /* +0x198 */
    jdouble (*GetDoubleField)(JNIEnv *, jobject, jfieldID); /* +0x19c */
    void (*SetObjectField)(JNIEnv *, jobject, jfieldID, jobject); /* +0x1a0 */
    void (*SetBooleanField)(JNIEnv *, jobject, jfieldID, jboolean); /* +0x1a4 */
    void (*SetByteField)(JNIEnv *, jobject, jfieldID, jbyte); /* +0x1a8 */
    void (*SetCharField)(JNIEnv *, jobject, jfieldID, jchar); /* +0x1ac */
    void (*SetShortField)(JNIEnv *, jobject, jfieldID, jshort); /* +0x1b0 */
    void (*SetIntField)(JNIEnv *, jobject, jfieldID, jint); /* +0x1b4 */
    void (*SetLongField)(JNIEnv *, jobject, jfieldID, jlong); /* +0x1b8 */
    void (*SetFloatField)(JNIEnv *, jobject, jfieldID, jfloat); /* +0x1bc */
    void (*SetDoubleField)(JNIEnv *, jobject, jfieldID, jdouble); /* +0x1c0 */
    jmethodID (*GetStaticMethodID)(JNIEnv *, jclass, char *, char *); /* +0x1c4 */
    jobject (*CallStaticObjectMethod)(JNIEnv *, jclass, jmethodID); /* +0x1c8 */
    jobject (*CallStaticObjectMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x1cc */
    jobject (*CallStaticObjectMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x1d0 */
    jboolean (*CallStaticBooleanMethod)(JNIEnv *, jclass, jmethodID); /* +0x1d4 */
    jboolean (*CallStaticBooleanMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x1d8 */
    jboolean (*CallStaticBooleanMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x1dc */
    jbyte (*CallStaticByteMethod)(JNIEnv *, jclass, jmethodID); /* +0x1e0 */
    jbyte (*CallStaticByteMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x1e4 */
    jbyte (*CallStaticByteMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x1e8 */
    jchar (*CallStaticCharMethod)(JNIEnv *, jclass, jmethodID); /* +0x1ec */
    jchar (*CallStaticCharMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x1f0 */
    jchar (*CallStaticCharMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x1f4 */
    jshort (*CallStaticShortMethod)(JNIEnv *, jclass, jmethodID); /* +0x1f8 */
    jshort (*CallStaticShortMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x1fc */
    jshort (*CallStaticShortMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x200 */
    jint (*CallStaticIntMethod)(JNIEnv *, jclass, jmethodID); /* +0x204 */
    jint (*CallStaticIntMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x208 */
    jint (*CallStaticIntMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x20c */
    jlong (*CallStaticLongMethod)(JNIEnv *, jclass, jmethodID); /* +0x210 */
    jlong (*CallStaticLongMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x214 */
    jlong (*CallStaticLongMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x218 */
    jfloat (*CallStaticFloatMethod)(JNIEnv *, jclass, jmethodID); /* +0x21c */
    jfloat (*CallStaticFloatMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x220 */
    jfloat (*CallStaticFloatMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x224 */
    jdouble (*CallStaticDoubleMethod)(JNIEnv *, jclass, jmethodID); /* +0x228 */
    jdouble (*CallStaticDoubleMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x22c */
    jdouble (*CallStaticDoubleMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x230 */
    void (*CallStaticVoidMethod)(JNIEnv *, jclass, jmethodID); /* +0x234 */
    void (*CallStaticVoidMethodV)(JNIEnv *, jclass, jmethodID, va_list); /* +0x238 */
    void (*CallStaticVoidMethodA)(JNIEnv *, jclass, jmethodID, jvalue *); /* +0x23c */
    jfieldID (*GetStaticFieldID)(JNIEnv *, jclass, char *, char *); /* +0x240 */
    jobject (*GetStaticObjectField)(JNIEnv *, jclass, jfieldID); /* +0x244 */
    jboolean (*GetStaticBooleanField)(JNIEnv *, jclass, jfieldID); /* +0x248 */
    jbyte (*GetStaticByteField)(JNIEnv *, jclass, jfieldID); /* +0x24c */
    jchar (*GetStaticCharField)(JNIEnv *, jclass, jfieldID); /* +0x250 */
    jshort (*GetStaticShortField)(JNIEnv *, jclass, jfieldID); /* +0x254 */
    jint (*GetStaticIntField)(JNIEnv *, jclass, jfieldID); /* +0x258 */
    jlong (*GetStaticLongField)(JNIEnv *, jclass, jfieldID); /* +0x25c */
    jfloat (*GetStaticFloatField)(JNIEnv *, jclass, jfieldID); /* +0x260 */
    jdouble (*GetStaticDoubleField)(JNIEnv *, jclass, jfieldID); /* +0x264 */
    void (*SetStaticObjectField)(JNIEnv *, jclass, jfieldID, jobject); /* +0x268 */
    void (*SetStaticBooleanField)(JNIEnv *, jclass, jfieldID, jboolean); /* +0x26c */
    void (*SetStaticByteField)(JNIEnv *, jclass, jfieldID, jbyte); /* +0x270 */
    void (*SetStaticCharField)(JNIEnv *, jclass, jfieldID, jchar); /* +0x274 */
    void (*SetStaticShortField)(JNIEnv *, jclass, jfieldID, jshort); /* +0x278 */
    void (*SetStaticIntField)(JNIEnv *, jclass, jfieldID, jint); /* +0x27c */
    void (*SetStaticLongField)(JNIEnv *, jclass, jfieldID, jlong); /* +0x280 */
    void (*SetStaticFloatField)(JNIEnv *, jclass, jfieldID, jfloat); /* +0x284 */
    void (*SetStaticDoubleField)(JNIEnv *, jclass, jfieldID, jdouble); /* +0x288 */
    jstring (*NewString)(JNIEnv *, jchar *, jsize); /* +0x28c */
    jsize (*GetStringLength)(JNIEnv *, jstring); /* +0x290 */
    jchar *(*GetStringChars)(JNIEnv *, jstring, jboolean *); /* +0x294 */
    void (*ReleaseStringChars)(JNIEnv *, jstring, jchar *); /* +0x298 */
    jstring (*NewStringUTF)(JNIEnv *, char *); /* +0x29c */
    jsize (*GetStringUTFLength)(JNIEnv *, jstring); /* +0x2a0 */
    char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); /* +0x2a4 */
    void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); /* +0x2a8 */
    jsize (*GetArrayLength)(JNIEnv *, jarray); /* +0x2ac */
    jobjectArray (*NewObjectArray)(JNIEnv *, jsize, jclass, jobject); /* +0x2b0 */
    jobject (*GetObjectArrayElement)(JNIEnv *, jobjectArray, jsize); /* +0x2b4 */
    void (*SetObjectArrayElement)(JNIEnv *, jobjectArray, jsize, jobject); /* +0x2b8 */
    jbooleanArray (*NewBooleanArray)(JNIEnv *, jsize); /* +0x2bc */
    jbyteArray (*NewByteArray)(JNIEnv *, jsize); /* +0x2c0 */
    jcharArray (*NewCharArray)(JNIEnv *, jsize); /* +0x2c4 */
    jshortArray (*NewShortArray)(JNIEnv *, jsize); /* +0x2c8 */
    jintArray (*NewIntArray)(JNIEnv *, jsize); /* +0x2cc */
    jlongArray (*NewLongArray)(JNIEnv *, jsize); /* +0x2d0 */
    jfloatArray (*NewFloatArray)(JNIEnv *, jsize); /* +0x2d4 */
    jdoubleArray (*NewDoubleArray)(JNIEnv *, jsize); /* +0x2d8 */
    jboolean *(*GetBooleanArrayElements)(JNIEnv *, jbooleanArray, jboolean *); /* +0x2dc */
    jbyte *(*GetByteArrayElements)(JNIEnv *, jbyteArray, jboolean *); /* +0x2e0 */
    jchar *(*GetCharArrayElements)(JNIEnv *, jcharArray, jboolean *); /* +0x2e4 */
    jshort *(*GetShortArrayElements)(JNIEnv *, jshortArray, jboolean *); /* +0x2e8 */
    jint *(*GetIntArrayElements)(JNIEnv *, jintArray, jboolean *); /* +0x2ec */
    jlong *(*GetLongArrayElements)(JNIEnv *, jlongArray, jboolean *); /* +0x2f0 */
    jfloat *(*GetFloatArrayElements)(JNIEnv *, jfloatArray, jboolean *); /* +0x2f4 */
    jdouble *(*GetDoubleArrayElements)(JNIEnv *, jdoubleArray, jboolean *); /* +0x2f8 */
    void (*ReleaseBooleanArrayElements)(JNIEnv *, jbooleanArray, jboolean *, jint); /* +0x2fc */
    void (*ReleaseByteArrayElements)(JNIEnv *, jbyteArray, jbyte *, jint); /* +0x300 */
    void (*ReleaseCharArrayElements)(JNIEnv *, jcharArray, jchar *, jint); /* +0x304 */
    void (*ReleaseShortArrayElements)(JNIEnv *, jshortArray, jshort *, jint); /* +0x308 */
    void (*ReleaseIntArrayElements)(JNIEnv *, jintArray, jint *, jint); /* +0x30c */
    void (*ReleaseLongArrayElements)(JNIEnv *, jlongArray, jlong *, jint); /* +0x310 */
    void (*ReleaseFloatArrayElements)(JNIEnv *, jfloatArray, jfloat *, jint); /* +0x314 */
    void (*ReleaseDoubleArrayElements)(JNIEnv *, jdoubleArray, jdouble *, jint); /* +0x318 */
    void (*GetBooleanArrayRegion)(JNIEnv *, jbooleanArray, jsize, jsize, jboolean *); /* +0x31c */
    void (*GetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, jbyte *); /* +0x320 */
    void (*GetCharArrayRegion)(JNIEnv *, jcharArray, jsize, jsize, jchar *); /* +0x324 */
    void (*GetShortArrayRegion)(JNIEnv *, jshortArray, jsize, jsize, jshort *); /* +0x328 */
    void (*GetIntArrayRegion)(JNIEnv *, jintArray, jsize, jsize, jint *); /* +0x32c */
    void (*GetLongArrayRegion)(JNIEnv *, jlongArray, jsize, jsize, jlong *); /* +0x330 */
    void (*GetFloatArrayRegion)(JNIEnv *, jfloatArray, jsize, jsize, jfloat *); /* +0x334 */
    void (*GetDoubleArrayRegion)(JNIEnv *, jdoubleArray, jsize, jsize, jdouble *); /* +0x338 */
    void (*SetBooleanArrayRegion)(JNIEnv *, jbooleanArray, jsize, jsize, jboolean *); /* +0x33c */
    void (*SetByteArrayRegion)(JNIEnv *, jbyteArray, jsize, jsize, jbyte *); /* +0x340 */
    void (*SetCharArrayRegion)(JNIEnv *, jcharArray, jsize, jsize, jchar *); /* +0x344 */
    void (*SetShortArrayRegion)(JNIEnv *, jshortArray, jsize, jsize, jshort *); /* +0x348 */
    void (*SetIntArrayRegion)(JNIEnv *, jintArray, jsize, jsize, jint *); /* +0x34c */
    void (*SetLongArrayRegion)(JNIEnv *, jlongArray, jsize, jsize, jlong *); /* +0x350 */
    void (*SetFloatArrayRegion)(JNIEnv *, jfloatArray, jsize, jsize, jfloat *); /* +0x354 */
    void (*SetDoubleArrayRegion)(JNIEnv *, jdoubleArray, jsize, jsize, jdouble *); /* +0x358 */
    jint (*RegisterNatives)(JNIEnv *, jclass, JNINativeMethod *, jint); /* +0x35c */
    jint (*UnregisterNatives)(JNIEnv *, jclass); /* +0x360 */
    jint (*MonitorEnter)(JNIEnv *, jobject); /* +0x364 */
    jint (*MonitorExit)(JNIEnv *, jobject); /* +0x368 */
    jint (*GetJavaVM)(JNIEnv *, JavaVM **); /* +0x36c */
    void (*GetStringRegion)(JNIEnv *, jstring, jsize, jsize, jchar *); /* +0x370 */
    void (*GetStringUTFRegion)(JNIEnv *, jstring, jsize, jsize, char *); /* +0x374 */
    void *(*GetPrimitiveArrayCritical)(JNIEnv *, jarray, jboolean *); /* +0x378 */
    void (*ReleasePrimitiveArrayCritical)(JNIEnv *, jarray, void *, jint); /* +0x37c */
    jchar *(*GetStringCritical)(JNIEnv *, jstring, jboolean *); /* +0x380 */
    void (*ReleaseStringCritical)(JNIEnv *, jstring, jchar *); /* +0x384 */
    jweak (*NewWeakGlobalRef)(JNIEnv *, jobject); /* +0x388 */
    void (*DeleteWeakGlobalRef)(JNIEnv *, jweak); /* +0x38c */
    jboolean (*ExceptionCheck)(JNIEnv *); /* +0x390 */
    jobject (*NewDirectByteBuffer)(JNIEnv *, void *, jlong); /* +0x394 */
    void *(*GetDirectBufferAddress)(JNIEnv *, jobject); /* +0x398 */
    jlong (*GetDirectBufferCapacity)(JNIEnv *, jobject); /* +0x39c */
    jobjectRefType (*GetObjectRefType)(JNIEnv *, jobject); /* +0x3a0 */
};
struct JNIInvokeInterface
{
    void *reserved0; /* +0x0 */
    void *reserved1; /* +0x4 */
    void *reserved2; /* +0x8 */
    jint (*DestroyJavaVM)(JavaVM *); /* +0xc */
    jint (*AttachCurrentThread)(JavaVM *, JNIEnv **, void *); /* +0x10 */
    jint (*DetachCurrentThread)(JavaVM *); /* +0x14 */
    jint (*GetEnv)(JavaVM *, void **, jint); /* +0x18 */
    jint (*AttachCurrentThreadAsDaemon)(JavaVM *, JNIEnv **, void *); /* +0x1c */
};
