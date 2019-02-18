#include <stdio.h>
#include <string.h>
#include <time.h>

#include "include/coolapk.h"

/* Reverse engineering by duangsuse using Radare2 / dwarview / dwarf_to_c
  radare2 3.3.0-git 21045 @ linux-x86-64 git.3.2.1-366-ga795cd647
  commit: a795cd647c64028137f77f0ad78719d768f7292a build: 2019-02-16__15:16:12 */

/**
/ (fcn) sym.Java_com_coolapk_market_util_AuthUtils_getAS 1988 ; external fun getAS(str: String): String @ line 53
|   sym.Java_com_coolapk_market_util_AuthUtils_getAS (int arg_14h, int arg_10h, int arg_ch, int arg_8h, int arg_10h_2);
|           ; var int var_ch_2 @ ebp-0xc
|           ; var int var_14ch @ ebp-0x14c
|           ; var int var_150h @ ebp-0x150
|           ; var int var_154h @ ebp-0x154
|           ; var int var_feh @ ebp-0xfe
|           ; var int var_158h @ ebp-0x158
|           ; var int var_15ch @ ebp-0x15c
|           ; var int var_160h @ ebp-0x160
|           ; var int var_164h @ ebp-0x164
|           ; var int var_168h @ ebp-0x168
|           ; var int var_16ch @ ebp-0x16c
|           ; var int var_11fh @ ebp-0x11f
|           ; var int var_147h @ ebp-0x147
|           ; var int var_13dh @ ebp-0x13d
|           ; var int var_170h @ ebp-0x170
|           ; var int var_174h @ ebp-0x174
|           ; var int var_178h @ ebp-0x178
|           ; var int var_17ch @ ebp-0x17c
|           ; var int var_180h @ ebp-0x180
|           ; var int var_184h @ ebp-0x184
|           ; var int var_188h @ ebp-0x188
|           ; var int var_18ch @ ebp-0x18c
|           ; var int var_190h @ ebp-0x190
|           ; var int var_194h @ ebp-0x194
|           ; var int var_198h @ ebp-0x198
|           ; var int var_1bch @ ebp-0x1bc
|           ; var int var_ddh @ ebp-0xdd    ; char *h
|           ; var int var_120h @ ebp-0x120
|           ; var int var_122h @ ebp-0x122  ; "et"
|           ; var int var_126h @ ebp-0x126  ; "mark"
|           ; var int var_12ah @ ebp-0x12a  ; "apk."
|           ; var int var_12eh @ ebp-0x12e  ; "cool"
|           ; var int var_132h @ ebp-0x132  ; *char = com.coolapk.market\00
|           ; var int var_19ch @ ebp-0x19c  ; *char nPackageName = getPackageName()
|           ; var int var_1a0h @ ebp-0x1a0  ; jstring packageName
|           ; var int var_1a4h @ ebp-0x1a4  ; jmethodID midGetPackageName
|           ; var int var_1a8h @ ebp-0x1a8  ; jclass android_content_Context
|           ; var int var_1c0h @ ebp-0x1c0  ; security_cookie
|           ; var int var_1ch @ ebp-0x1c
|           ; var int var_1b8h @ ebp-0x1b8  ; str
|           ; arg int arg_14h @ ebp+0x14    ; jstring str ~JNIEnv *env
|           ; var int var_1b4h @ ebp-0x1b4  ; obj
|           ; arg int arg_10h @ ebp+0x10    ; jobject obj
|           ; var int var_1b0h @ ebp-0x1b0  ; entryObject
|           ; arg int arg_ch @ ebp+0xc      ; jobject entryObject
|           ; var int var_1ach @ ebp-0x1ac  ; JNIEnv *env ~jstr
|           ; arg int arg_8h @ ebp+0x8      ; env ~jstring jstr
|           ; var int var_4h @ esp+0x4
|           ; var int var_8h @ esp+0x8
|           ; var int var_ch @ esp+0xc
|           ; arg int arg_10h_2 @ esp+0x10
|           0x00001d2a      55             push ebp
|           0x00001d2b      89e5           mov ebp, esp
|           0x00001d2d      57             push edi
|           0x00001d2e      56             push esi
|           0x00001d2f      53             push ebx
|           0x00001d30      8da42434feff.  lea esp, [esp - 0x1cc]
|           0x00001d37      e864e9ffff     call sym.__x86.get_pc_thunk.bx
|           0x00001d3c      81c390220000   add ebx, 0x2290
|           0x00001d42      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0 ; env
|           0x00001d45      898554feffff   mov dword [var_1ach], eax   ; env
|           0x00001d4b      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
|           0x00001d4e      898550feffff   mov dword [var_1b0h], eax
|           0x00001d54      8b4510         mov eax, dword [arg_10h]    ; [0x10:4]=0x30003
|           0x00001d57      89854cfeffff   mov dword [var_1b4h], eax
|           0x00001d5d      8b4514         mov eax, dword [arg_14h]    ; [0x14:4]=1
|           0x00001d60      898548feffff   mov dword [var_1b8h], eax
|           0x00001d66      8b83fcffffff   mov eax, dword [ebx - 4]    ; sp[-1]
|           0x00001d6c      8b00           mov eax, dword [eax]
|           0x00001d6e      8945e4         mov dword [var_1ch], eax
|           0x00001d71      89e0           mov eax, esp
|           0x00001d73      898540feffff   mov dword [var_1c0h], eax
|           0x00001d79      8b8554feffff   mov eax, dword [var_1ach]   ; env
|           0x00001d7f      8b00           mov eax, dword [eax]        : ax = *env
|           0x00001d81      8b407c         mov eax, dword [eax + 0x7c] ; [0x7c:4]=0x3ebc segment.GNU_RELRO ; '|' ; jclass (*GetObjectClass)(JNIEnv *, jobject); (+0x7c)
|           0x00001d84      8b954cfeffff   mov edx, dword [var_1b4h]
|           0x00001d8a      89542404       mov dword [var_4h], edx     ; arg2 = obj
|           0x00001d8e      8b9554feffff   mov edx, dword [var_1ach]
|           0x00001d94      891424         mov dword [esp], edx        ; arg1 = env
|           0x00001d97      ffd0           call eax                    ; GetObjectClass(env, obj);
|           0x00001d99      898558feffff   mov dword [var_1a8h], eax   ; Line 55 ~= android_content_Context = env->GetObjectClass(env, obj);
|           0x00001d9f      8b8554feffff   mov eax, dword [var_1ach]
|           0x00001da5      8b00           mov eax, dword [eax]
|           0x00001da7      8b8084000000   mov eax, dword [eax + 0x84] ; [0x84:4]=328 ; jmethodID (*GetMethodID)(JNIEnv *, jclass, char *name, char *sig); (+0x84)
|           0x00001dad      8d937de6ffff   lea edx, [ebx - 0x1983]                    ; sig:GetMethodID = ()Ljava/lang/String; (offset:getPackageName + 21)
|           0x00001db3      8954240c       mov dword [var_ch], edx
|           0x00001db7      8d9392e6ffff   lea edx, [ebx - 0x196e]                    ; name:GetMethodID = getPackageName
|           0x00001dbd      89542408       mov dword [var_8h], edx
|           0x00001dc1      8b9558feffff   mov edx, dword [var_1a8h]
|           0x00001dc7      89542404       mov dword [var_4h], edx                    ; arg2 = android_content_Context
|           0x00001dcb      8b9554feffff   mov edx, dword [var_1ach]
|           0x00001dd1      891424         mov dword [esp], edx
|           0x00001dd4      ffd0           call eax                                   ; env->GetMethodID(env, android_content_Context:arg2, name:[ebx - 0x196e], sig:[ebx - 0x1983])
|           0x00001dd6      89855cfeffff   mov dword [var_1a4h], eax    ; Line 56 ~= midGetPackageName = env->GetMethodID(env, android_content_Context, "getPackageName", "()Ljava/lang/String;");
|           0x00001ddc      8b8554feffff   mov eax, dword [var_1ach]
|           0x00001de2      8b00           mov eax, dword [eax]
|           0x00001de4      8b8088000000   mov eax, dword [eax + 0x88] ; [0x88:4]=328 ; jobject (*CallObjectMethod)(JNIEnv *, jobject, jmethodID); (+0x88)
|           0x00001dea      8b955cfeffff   mov edx, dword [var_1a4h]
|           0x00001df0      89542408       mov dword [var_8h], edx     ; arg3 = midGetPackageName
|           0x00001df4      8b954cfeffff   mov edx, dword [var_1b4h]
|           0x00001dfa      89542404       mov dword [var_4h], edx     ; arg2 = obj
|           0x00001dfe      8b9554feffff   mov edx, dword [var_1ach]
|           0x00001e04      891424         mov dword [esp], edx        ; arg1 = env
|           0x00001e07      ffd0           call eax                    ; CallObjectMethod(env, obj, midGetPackageName)
|           0x00001e09      898560feffff   mov dword [var_1a0h], eax   ; Line 60 ~= packageName = env->CallObjectMethod(env, obj, midGetPackageName);
|           0x00001e0f      8b8554feffff   mov eax, dword [var_1ach]
|           0x00001e15      8b00           mov eax, dword [eax]
|           0x00001e17      8b80a4020000   mov eax, dword [eax + 0x2a4] ; [0x2a4:4]=0x80012 ; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)
|           0x00001e1d      c74424080000.  mov dword [var_8h], 0        ; arg3 = false
|           0x00001e25      8b9560feffff   mov edx, dword [var_1a0h]
|           0x00001e2b      89542404       mov dword [var_4h], edx      ; arg2 = packageName
|           0x00001e2f      8b9554feffff   mov edx, dword [var_1ach]
|           0x00001e35      891424         mov dword [esp], edx         ; arg1 = env
|           0x00001e38      ffd0           call eax                     ; GetStringUTFChars(env, packageName, false)
|           0x00001e3a      898564feffff   mov dword [var_19ch], eax    ; Line 61 ~= nPackageName = env->GetStringUTFChars(env, packageName, 0);
|           0x00001e40      c785cefeffff.  mov dword [var_132h], 0x2e6d6f63 ; 'com.'
|           0x00001e4a      c785d2feffff.  mov dword [var_12eh], 0x6c6f6f63 ; 'cool'
|           0x00001e54      c785d6feffff.  mov dword [var_12ah], 0x2e6b7061 ; 'apk.'
|           0x00001e5e      c785dafeffff.  mov dword [var_126h], 0x6b72616d ; 'mark'
|           0x00001e68      66c785defeff.  mov word [var_122h], 0x7465 ; 'et'
|           0x00001e71      c685e0feffff.  mov byte [var_120h], 0
|           0x00001e78      8d85cefeffff   lea eax, [var_132h]
|           0x00001e7e      89442404       mov dword [var_4h], eax     ; arg2 = "com.coolapk.market" ; （迫真包名校验）
|           0x00001e82      8b8564feffff   mov eax, dword [var_19ch]
|           0x00001e88      890424         mov dword [esp], eax        ; arg1 = packageName
|           0x00001e8b      e830e7ffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
|           0x00001e90      85c0           test eax, eax               ; Line 62 ~= if (strcmp(packageName, "com.coolapk.market") != 0) {
|       ,=< 0x00001e92      7470           je 0x1f04                   ; jump if equals (zero)
|       |   0x00001e94      8b8554feffff   mov eax, dword [var_1ach]
|       |   0x00001e9a      8b00           mov eax, dword [eax]
|       |   0x00001e9c      8b405c         mov eax, dword [eax + 0x5c] ; [0x5c:4]=0 ; '\' ; void (*DeleteLocalRef)(JNIEnv *, jobject); (+0x5c)
|       |   0x00001e9f      8b9558feffff   mov edx, dword [var_1a8h]
|       |   0x00001ea5      89542404       mov dword [var_4h], edx     ; arg2 = android_content_Context
|       |   0x00001ea9      8b9554feffff   mov edx, dword [var_1ach]
|       |   0x00001eaf      891424         mov dword [esp], edx        ; arg1 = env
|       |   0x00001eb2      ffd0           call eax                    ; DeleteLocalRef(env, arg2) ; Line ??? ~= env->DeleteLocalRef(env, android_content_Context);
|       |   0x00001eb4      8b8554feffff   mov eax, dword [var_1ach]
|       |   0x00001eba      8b00           mov eax, dword [eax]
|       |   0x00001ebc      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172 ; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)
|       |   0x00001ec2      8b9564feffff   mov edx, dword [var_19ch]
|       |   0x00001ec8      89542408       mov dword [var_8h], edx      ; arg3 = packageNameChars (nPackageName)
|       |   0x00001ecc      8b9560feffff   mov edx, dword [var_1a0h]
|       |   0x00001ed2      89542404       mov dword [var_4h], edx      ; arg2 = packageName
|       |   0x00001ed6      8b9554feffff   mov edx, dword [var_1ach]
|       |   0x00001edc      891424         mov dword [esp], edx
|       |   0x00001edf      ffd0           call eax                     ; ReleaseStringUTFChars(env, packageName, nPackageName) ; Line ??? ~= env->ReleaseStringUTFChars(env, packageName, nPackageName);
|       |   0x00001ee1      8b8554feffff   mov eax, dword [var_1ach]
|       |   0x00001ee7      8b00           mov eax, dword [eax]
|       |   0x00001ee9      8b4054         mov eax, dword [eax + 0x54]  ; [0x54:4]=1 ; 'T' ; jobject (*NewGlobalRef)(JNIEnv *, jobject); (+0x54)
|       |   0x00001eec      c74424040000.  mov dword [var_4h], 0        ; C NULL
|       |   0x00001ef4      8b9554feffff   mov edx, dword [var_1ach]
|       |   0x00001efa      891424         mov dword [esp], edx         ; env
|       |   0x00001efd      ffd0           call eax                     ; NewGlobalRef(env, NULL)
|      ,==< 0x00001eff      e9c8050000     jmp 0x24cc                   ; return ; Line ??? ~= return env->NewGlobalRef(env, NULL);
|      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1e92)
|      |`-> 0x00001f04      8d8523ffffff   lea eax, [var_ddh]           ; } // with a new soul~
|      |    0x00001f0a      8d93a8e6ffff   lea edx, [ebx - 0x1958]      ; [ebx - 0x1968] (offset @ .rodata, offset:getPackageName - 22) = ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO
|      |    0x00001f10      c78544feffff.  mov dword [var_1bch], 0xc1   ; = 193, sizeof("ld...") = 193
|      |    0x00001f1a      89c1           mov ecx, eax                 ; vddh
|      |    0x00001f1c      83e101         and ecx, 1                   ; vddh & true
|      |    0x00001f1f      85c9           test ecx, ecx                ; if (vddh != NULL) {
|      |,=< 0x00001f21      7412           jz 0x1f35                    ; it's true first time
|      ||   0x00001f23      0fb60a         movzx ecx, byte [edx]        ; offset .rodata.ld...
|      ||   0x00001f26      8808           mov byte [eax], cl           ; (char) ax = ldTM[i] ; cp[0] = ldTM[0]
|      ||   0x00001f28      8d4001         lea eax, [eax + 1]           ; ax = cp[1]
|      ||   0x00001f2b      8d5201         lea edx, [edx + 1]           ; dx = h[1]
|      ||   0x00001f2e      83ad44feffff.  sub dword [var_1bch], 1      ; iter--
|      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f21)
|      |`-> 0x00001f35      89c1           mov ecx, eax                 ; }
|      |    0x00001f37      83e102         and ecx, 2                   ; if (cp[1] & 2)
|      |    0x00001f3a      85c9           test ecx, ecx
|      |,=< 0x00001f3c      7413           jz 0x1f51
|      ||   0x00001f3e      0fb70a         movzx ecx, word [edx]        ; cx = h[1]
|      ||   0x00001f41      668908         mov word [eax], cx           ; cp[1] = h[1]
|      ||   0x00001f44      8d4002         lea eax, [eax + 2]           ; cp += 2
|      ||   0x00001f47      8d5202         lea edx, [edx + 2]           ; hp += 2
|      ||   0x00001f4a      83ad44feffff.  sub dword [var_1bch], 2      ; iter -= 2
|      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f3c)
|      |`-> 0x00001f51      8b8d44feffff   mov ecx, dword [var_1bch]    ; cx = iter
|      |    0x00001f57      c1e902         shr ecx, 2                   ; cx /= 4
|      |    0x00001f5a      89c7           mov edi, eax                 ; cp
|      |    0x00001f5c      89d6           mov esi, edx                 ; h
|      |    0x00001f5e      f3a5           rep movsd dword es:[edi], dword ptr [esi]
|      |    0x00001f60      89f2           mov edx, esi                 ; h
|      |    0x00001f62      89f8           mov eax, edi                 ; cp
|      |    0x00001f64      b900000000     mov ecx, 0
|      |    0x00001f69      8bb544feffff   mov esi, dword [var_1bch]    ; iter
|      |    0x00001f6f      83e602         and esi, 2                   ; iter & 2
|      |    0x00001f72      85f6           test esi, esi
|      |,=< 0x00001f74      740b           jz 0x1f81                    ; if (iter & 2 != 0) {
|      ||   0x00001f76      0fb7340a       movzx esi, word [edx + ecx]  ; si = h[0]
|      ||   0x00001f7a      66893408       mov word [eax + ecx], si     ; cp[0] = si
|      ||   0x00001f7e      83c102         add ecx, 2                   ; cx += 2
|      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f74) ; }
|      |`-> 0x00001f81      8bb544feffff   mov esi, dword [var_1bch]
|      |    0x00001f87      83e601         and esi, 1                   ; if (iter & 1)
|      |    0x00001f8a      85f6           test esi, esi
|      |,=< 0x00001f8c      7407           jz 0x1f95
|      ||   0x00001f8e      0fb6140a       movzx edx, byte [edx + ecx]  ; c = h[cx]
|      ||   0x00001f92      881408         mov byte [eax + ecx], dl     ; cp[cx] = c
|      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f8c)
|      |`-> 0x00001f95      8d8523ffffff   lea eax, [var_ddh]
|      |    0x00001f9b      890424         mov dword [esp], eax        ; arg1 = vddh
|      |    0x00001f9e      e8a4fbffff     call sym.r                  ; (inout) reverse a string
|      |    0x00001fa3      8d8523ffffff   lea eax, [var_ddh]
|      |    0x00001fa9      890424         mov dword [esp], eax        ; arg1 = vddh
|      |    0x00001fac      e8f3e6ffff     call sym.BDL                ; Base64 decode length(char *codebuf)
|      |    0x00001fb1      898568feffff   mov dword [var_198h], eax
|      |    0x00001fb7      8b8568feffff   mov eax, dword [var_198h]
|      |    0x00001fbd      8d50ff         lea edx, [eax - 1]
|      |    0x00001fc0      89956cfeffff   mov dword [var_194h], edx
|      |    0x00001fc6      89c2           mov edx, eax
|      |    0x00001fc8      b810000000     mov eax, 0x10
|      |    0x00001fcd      83e801         sub eax, 1
|      |    0x00001fd0      01d0           add eax, edx
|      |    0x00001fd2      bf10000000     mov edi, 0x10
|      |    0x00001fd7      ba00000000     mov edx, 0
|      |    0x00001fdc      f7f7           div edi
|      |    0x00001fde      6bc010         imul eax, eax, 0x10
|      |    0x00001fe1      29c4           sub esp, eax
|      |    0x00001fe3      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x00001fe7      83c000         add eax, 0
|      |    0x00001fea      898570feffff   mov dword [var_190h], eax
|      |    0x00001ff0      8b8570feffff   mov eax, dword [var_190h]
|      |    0x00001ff6      8d9523ffffff   lea edx, [var_ddh]
|      |    0x00001ffc      89542404       mov dword [var_4h], edx     ; arg2 = var_ddh
|      |    0x00002000      890424         mov dword [esp], eax        ; arg1 = var_190h
|      |    0x00002003      e8bcfbffff     call sym.bd                 ; Base64 decode(char *out, const char *codestr)
|      |    0x00002008      8b8570feffff   mov eax, dword [var_190h]
|      |    0x0000200e      890424         mov dword [esp], eax        ; arg1 = var_190h
|      |    0x00002011      e831fbffff     call sym.r                  ; reverse a char buffer
|      |    0x00002016      8b8570feffff   mov eax, dword [var_190h]
|      |    0x0000201c      890424         mov dword [esp], eax
|      |    0x0000201f      e87ce5ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x00002024      83e840         sub eax, 0x40               ; '@'
|      |    0x00002027      898574feffff   mov dword [var_18ch], eax
|      |    0x0000202d      8b8574feffff   mov eax, dword [var_18ch]
|      |    0x00002033      83c001         add eax, 1
|      |    0x00002036      8d50ff         lea edx, [eax - 1]
|      |    0x00002039      899578feffff   mov dword [var_188h], edx
|      |    0x0000203f      89c2           mov edx, eax
|      |    0x00002041      b810000000     mov eax, 0x10
|      |    0x00002046      83e801         sub eax, 1
|      |    0x00002049      01d0           add eax, edx
|      |    0x0000204b      bf10000000     mov edi, 0x10
|      |    0x00002050      ba00000000     mov edx, 0
|      |    0x00002055      f7f7           div edi
|      |    0x00002057      6bc010         imul eax, eax, 0x10
|      |    0x0000205a      29c4           sub esp, eax
|      |    0x0000205c      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x00002060      83c000         add eax, 0
|      |    0x00002063      89857cfeffff   mov dword [var_184h], eax
|      |    0x00002069      8b9574feffff   mov edx, dword [var_18ch]
|      |    0x0000206f      8b8570feffff   mov eax, dword [var_190h]
|      |    0x00002075      8d4820         lea ecx, [eax + 0x20]       ; "l\x8c"
|      |    0x00002078      8b857cfeffff   mov eax, dword [var_184h]
|      |    0x0000207e      89542408       mov dword [var_8h], edx
|      |    0x00002082      894c2404       mov dword [var_4h], ecx
|      |    0x00002086      890424         mov dword [esp], eax
|      |    0x00002089      e8f2e4ffff     call sym.imp.memcpy         ; void *memcpy(void *s1, const void *s2, size_t n)
|      |    0x0000208e      8b957cfeffff   mov edx, dword [var_184h]
|      |    0x00002094      8b8574feffff   mov eax, dword [var_18ch]
|      |    0x0000209a      01d0           add eax, edx
|      |    0x0000209c      c60000         mov byte [eax], 0
|      |    0x0000209f      8b857cfeffff   mov eax, dword [var_184h]
|      |    0x000020a5      890424         mov dword [esp], eax
|      |    0x000020a8      e8f7e5ffff     call sym.BDL
|      |    0x000020ad      898580feffff   mov dword [var_180h], eax
|      |    0x000020b3      8b8580feffff   mov eax, dword [var_180h]
|      |    0x000020b9      8d50ff         lea edx, [eax - 1]
|      |    0x000020bc      899584feffff   mov dword [var_17ch], edx
|      |    0x000020c2      89c2           mov edx, eax
|      |    0x000020c4      b810000000     mov eax, 0x10
|      |    0x000020c9      83e801         sub eax, 1
|      |    0x000020cc      01d0           add eax, edx
|      |    0x000020ce      bf10000000     mov edi, 0x10
|      |    0x000020d3      ba00000000     mov edx, 0
|      |    0x000020d8      f7f7           div edi
|      |    0x000020da      6bc010         imul eax, eax, 0x10
|      |    0x000020dd      29c4           sub esp, eax
|      |    0x000020df      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x000020e3      83c000         add eax, 0
|      |    0x000020e6      898588feffff   mov dword [var_178h], eax
|      |    0x000020ec      8b957cfeffff   mov edx, dword [var_184h]    ; local_in
|      |    0x000020f2      8b8588feffff   mov eax, dword [var_178h]    ; local_out
|      |    0x000020f8      89542404       mov dword [var_4h], edx      ; arg2 = dx
|      |    0x000020fc      890424         mov dword [esp], eax         ; ax = out
|      |    0x000020ff      e8c0faffff     call sym.bd                  ; bd(out, base64)
|      |    0x00002104      8b8554feffff   mov eax, dword [var_1ach]
|      |    0x0000210a      8b00           mov eax, dword [eax]
|      |    0x0000210c      8b80a4020000   mov eax, dword [eax + 0x2a4] ; [0x2a4:4]=0x80012 ; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)
|      |    0x00002112      c74424080000.  mov dword [var_8h], 0
|      |    0x0000211a      8b9548feffff   mov edx, dword [var_1b8h]
|      |    0x00002120      89542404       mov dword [var_4h], edx
|      |    0x00002124      8b9554feffff   mov edx, dword [var_1ach]
|      |    0x0000212a      891424         mov dword [esp], edx
|      |    0x0000212d      ffd0           call eax
|      |    0x0000212f      89858cfeffff   mov dword [var_174h], eax
|      |    0x00002135      c70424000000.  mov dword [esp], 0
|      |    0x0000213c      e88fe4ffff     call sym.imp.time           ; time_t time(time_t *timer)
|      |    0x00002141      898590feffff   mov dword [var_170h], eax
|      |    0x00002147      8b8590feffff   mov eax, dword [var_170h]
|      |    0x0000214d      89442408       mov dword [var_8h], eax
|      |    0x00002151      8d83a1e6ffff   lea eax, [ebx - 0x195f]     ; offset:getPackageName(0x196e) - 15
|      |    0x00002157      89442404       mov dword [var_4h], eax     ; .rodata: "%d"
|      |    0x0000215b      8d85c3feffff   lea eax, [var_13dh]
|      |    0x00002161      890424         mov dword [esp], eax
|      |    0x00002164      e847e4ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
|      |    0x00002169      8b8590feffff   mov eax, dword [var_170h]
|      |    0x0000216f      89442408       mov dword [var_8h], eax
|      |    0x00002173      8d83a4e6ffff   lea eax, [ebx - 0x195c]     ; offset:getPackageName(0x196e) - 18
|      |    0x00002179      89442404       mov dword [var_4h], eax     ; .rodata: "%x"
|      |    0x0000217d      8d85b9feffff   lea eax, [var_147h]
|      |    0x00002183      890424         mov dword [esp], eax
|      |    0x00002186      e825e4ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
|      |    0x0000218b      8d85c3feffff   lea eax, [var_13dh]
|      |    0x00002191      89442404       mov dword [var_4h], eax
|      |    0x00002195      8d85e1feffff   lea eax, [var_11fh]
|      |    0x0000219b      890424         mov dword [esp], eax
|      |    0x0000219e      e84dfaffff     call sym.me
|      |    0x000021a3      8b8588feffff   mov eax, dword [var_178h]
|      |    0x000021a9      890424         mov dword [esp], eax
|      |    0x000021ac      e8efe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x000021b1      89c6           mov esi, eax
|      |    0x000021b3      8b858cfeffff   mov eax, dword [var_174h]
|      |    0x000021b9      890424         mov dword [esp], eax
|      |    0x000021bc      e8dfe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x000021c1      01c6           add esi, eax
|      |    0x000021c3      8b8564feffff   mov eax, dword [var_19ch]
|      |    0x000021c9      890424         mov dword [esp], eax
|      |    0x000021cc      e8cfe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x000021d1      01f0           add eax, esi
|      |    0x000021d3      83c023         add eax, 0x23               ; '#'
|      |    0x000021d6      898594feffff   mov dword [var_16ch], eax
|      |    0x000021dc      8b8594feffff   mov eax, dword [var_16ch]
|      |    0x000021e2      8d50ff         lea edx, [eax - 1]
|      |    0x000021e5      899598feffff   mov dword [var_168h], edx
|      |    0x000021eb      89c2           mov edx, eax
|      |    0x000021ed      b810000000     mov eax, 0x10
|      |    0x000021f2      83e801         sub eax, 1
|      |    0x000021f5      01d0           add eax, edx
|      |    0x000021f7      bf10000000     mov edi, 0x10
|      |    0x000021fc      ba00000000     mov edx, 0
|      |    0x00002201      f7f7           div edi
|      |    0x00002203      6bc010         imul eax, eax, 0x10
|      |    0x00002206      29c4           sub esp, eax
|      |    0x00002208      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x0000220c      83c000         add eax, 0
|      |    0x0000220f      89859cfeffff   mov dword [var_164h], eax
|      |    0x00002215      8b9588feffff   mov edx, dword [var_178h]
|      |    0x0000221b      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x00002221      89542404       mov dword [var_4h], edx
|      |    0x00002225      890424         mov dword [esp], eax
|      |    0x00002228      e8b3e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x0000222d      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x00002233      8d95e1feffff   lea edx, [var_11fh]
|      |    0x00002239      89542404       mov dword [var_4h], edx
|      |    0x0000223d      890424         mov dword [esp], eax
|      |    0x00002240      e89be3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x00002245      8bb59cfeffff   mov esi, dword [var_164h]
|      |    0x0000224b      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x00002251      b9ffffffff     mov ecx, 0xffffffff         ; -1
|      |    0x00002256      89c2           mov edx, eax
|      |    0x00002258      b800000000     mov eax, 0
|      |    0x0000225d      89d7           mov edi, edx
|      |    0x0000225f      f2ae           repne scasb al, byte es:[edi]
|      |    0x00002261      89c8           mov eax, ecx
|      |    0x00002263      f7d0           not eax
|      |    0x00002265      83e801         sub eax, 1
|      |    0x00002268      01f0           add eax, esi
|      |    0x0000226a      66c7002400     mov word [eax], 0x24        ; '$' ; [0x24:2]=0
|      |    0x0000226f      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x00002275      8b958cfeffff   mov edx, dword [var_174h]
|      |    0x0000227b      89542404       mov dword [var_4h], edx
|      |    0x0000227f      890424         mov dword [esp], eax
|      |    0x00002282      e859e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x00002287      8bb59cfeffff   mov esi, dword [var_164h]
|      |    0x0000228d      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x00002293      b9ffffffff     mov ecx, 0xffffffff         ; -1
|      |    0x00002298      89c2           mov edx, eax
|      |    0x0000229a      b800000000     mov eax, 0
|      |    0x0000229f      89d7           mov edi, edx
|      |    0x000022a1      f2ae           repne scasb al, byte es:[edi]
|      |    0x000022a3      89c8           mov eax, ecx
|      |    0x000022a5      f7d0           not eax
|      |    0x000022a7      83e801         sub eax, 1
|      |    0x000022aa      01f0           add eax, esi
|      |    0x000022ac      66c7002600     mov word [eax], 0x26        ; '&' ; [0x26:2]=0
|      |    0x000022b1      8b859cfeffff   mov eax, dword [var_164h]
|      |    0x000022b7      8b9564feffff   mov edx, dword [var_19ch]
|      |    0x000022bd      89542404       mov dword [var_4h], edx
|      |    0x000022c1      890424         mov dword [esp], eax
|      |    0x000022c4      e817e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x000022c9      8b8594feffff   mov eax, dword [var_16ch]
|      |    0x000022cf      890424         mov dword [esp], eax
|      |    0x000022d2      e80ae6ffff     call sym.BEL
|      |    0x000022d7      8985a0feffff   mov dword [var_160h], eax
|      |    0x000022dd      8b85a0feffff   mov eax, dword [var_160h]
|      |    0x000022e3      8d50ff         lea edx, [eax - 1]
|      |    0x000022e6      8995a4feffff   mov dword [var_15ch], edx
|      |    0x000022ec      89c2           mov edx, eax
|      |    0x000022ee      b810000000     mov eax, 0x10
|      |    0x000022f3      83e801         sub eax, 1
|      |    0x000022f6      01d0           add eax, edx
|      |    0x000022f8      bf10000000     mov edi, 0x10
|      |    0x000022fd      ba00000000     mov edx, 0
|      |    0x00002302      f7f7           div edi
|      |    0x00002304      6bc010         imul eax, eax, 0x10
|      |    0x00002307      29c4           sub esp, eax
|      |    0x00002309      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x0000230d      83c000         add eax, 0
|      |    0x00002310      8985a8feffff   mov dword [var_158h], eax
|      |    0x00002316      8b959cfeffff   mov edx, dword [var_164h]
|      |    0x0000231c      8b85a8feffff   mov eax, dword [var_158h]
|      |    0x00002322      89542404       mov dword [var_4h], edx
|      |    0x00002326      890424         mov dword [esp], eax
|      |    0x00002329      e8bbf9ffff     call sym.be
|      |    0x0000232e      8b85a8feffff   mov eax, dword [var_158h]
|      |    0x00002334      89442404       mov dword [var_4h], eax
|      |    0x00002338      8d8502ffffff   lea eax, [var_feh]
|      |    0x0000233e      890424         mov dword [esp], eax
|      |    0x00002341      e8aaf8ffff     call sym.me
|      |    0x00002346      8d8502ffffff   lea eax, [var_feh]
|      |    0x0000234c      890424         mov dword [esp], eax
|      |    0x0000234f      e84ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x00002354      89c6           mov esi, eax
|      |    0x00002356      8b858cfeffff   mov eax, dword [var_174h]
|      |    0x0000235c      890424         mov dword [esp], eax
|      |    0x0000235f      e83ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x00002364      01c6           add esi, eax
|      |    0x00002366      8d85b9feffff   lea eax, [var_147h]
|      |    0x0000236c      890424         mov dword [esp], eax
|      |    0x0000236f      e82ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|      |    0x00002374      01f0           add eax, esi
|      |    0x00002376      83c002         add eax, 2
|      |    0x00002379      8985acfeffff   mov dword [var_154h], eax
|      |    0x0000237f      8b85acfeffff   mov eax, dword [var_154h]
|      |    0x00002385      8d50ff         lea edx, [eax - 1]
|      |    0x00002388      8995b0feffff   mov dword [var_150h], edx
|      |    0x0000238e      89c2           mov edx, eax
|      |    0x00002390      b810000000     mov eax, 0x10
|      |    0x00002395      83e801         sub eax, 1
|      |    0x00002398      01d0           add eax, edx
|      |    0x0000239a      bf10000000     mov edi, 0x10
|      |    0x0000239f      ba00000000     mov edx, 0
|      |    0x000023a4      f7f7           div edi
|      |    0x000023a6      6bc010         imul eax, eax, 0x10
|      |    0x000023a9      29c4           sub esp, eax
|      |    0x000023ab      8d442410       lea eax, [arg_10h_2]        ; 0x10
|      |    0x000023af      83c000         add eax, 0
|      |    0x000023b2      8985b4feffff   mov dword [var_14ch], eax
|      |    0x000023b8      8b85b4feffff   mov eax, dword [var_14ch]
|      |    0x000023be      8d9502ffffff   lea edx, [var_feh]
|      |    0x000023c4      89542404       mov dword [var_4h], edx
|      |    0x000023c8      890424         mov dword [esp], eax
|      |    0x000023cb      e810e2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x000023d0      8b85b4feffff   mov eax, dword [var_14ch]
|      |    0x000023d6      8b958cfeffff   mov edx, dword [var_174h]
|      |    0x000023dc      89542404       mov dword [var_4h], edx
|      |    0x000023e0      890424         mov dword [esp], eax
|      |    0x000023e3      e8f8e1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x000023e8      8bb5b4feffff   mov esi, dword [var_14ch]
|      |    0x000023ee      8b85b4feffff   mov eax, dword [var_14ch]
|      |    0x000023f4      b9ffffffff     mov ecx, 0xffffffff         ; -1
|      |    0x000023f9      89c2           mov edx, eax
|      |    ; DATA XREF from sym.bd (0x1bd1)
|      |    0x000023fb      b800000000     mov eax, 0
|      |    0x00002400      89d7           mov edi, edx
|      |    0x00002402      f2ae           repne scasb al, byte es:[edi]
|      |    0x00002404      89c8           mov eax, ecx
|      |    0x00002406      f7d0           not eax
|      |    0x00002408      83e801         sub eax, 1
|      |    0x0000240b      01f0           add eax, esi
|      |    0x0000240d      66c7003078     mov word [eax], 0x7830      ; '0x' ; [0x7830:2]=0xffff
|      |    0x00002412      c6400200       mov byte [eax + 2], 0
|      |    0x00002416      8b85b4feffff   mov eax, dword [var_14ch]
|      |    0x0000241c      8d95b9feffff   lea edx, [var_147h]
|      |    0x00002422      89542404       mov dword [var_4h], edx
|      |    0x00002426      890424         mov dword [esp], eax
|      |    0x00002429      e8b2e1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
|      |    0x0000242e      8b8554feffff   mov eax, dword [var_1ach]
|      |    0x00002434      8b00           mov eax, dword [eax]
|      |    0x00002436      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172
|      |    0x0000243c      8b958cfeffff   mov edx, dword [var_174h]
|      |    0x00002442      89542408       mov dword [var_8h], edx
|      |    0x00002446      8b9548feffff   mov edx, dword [var_1b8h]
|      |    0x0000244c      89542404       mov dword [var_4h], edx
|      |    0x00002450      8b9554feffff   mov edx, dword [var_1ach]
|      |    0x00002456      891424         mov dword [esp], edx
|      |    0x00002459      ffd0           call eax
|      |    0x0000245b      8b8554feffff   mov eax, dword [var_1ach]
|      |    0x00002461      8b00           mov eax, dword [eax]
|      |    0x00002463      8b405c         mov eax, dword [eax + 0x5c] ; [0x5c:4]=0 ; '\'
|      |    0x00002466      8b9558feffff   mov edx, dword [var_1a8h]
|      |    0x0000246c      89542404       mov dword [var_4h], edx
|      |    0x00002470      8b9554feffff   mov edx, dword [var_1ach]
|      |    0x00002476      891424         mov dword [esp], edx
|      |    0x00002479      ffd0           call eax
|      |    0x0000247b      8b8554feffff   mov eax, dword [var_1ach]
|      |    0x00002481      8b00           mov eax, dword [eax]
|      |    0x00002483      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172
|      |    0x00002489      8b9564feffff   mov edx, dword [var_19ch]
|      |    0x0000248f      89542408       mov dword [var_8h], edx
|      |    0x00002493      8b9560feffff   mov edx, dword [var_1a0h]
|      |    0x00002499      89542404       mov dword [var_4h], edx
|      |    0x0000249d      8b9554feffff   mov edx, dword [var_1ach]
|      |    0x000024a3      891424         mov dword [esp], edx
|      |    0x000024a6      ffd0           call eax
|      |    0x000024a8      8b8554feffff   mov eax, dword [var_1ach]
|      |    0x000024ae      8b00           mov eax, dword [eax]
|      |    0x000024b0      8b809c020000   mov eax, dword [eax + sym.Java_com_coolapk_market_util_AuthUtils_getAS] ; [0x29c:4]=0x1d2a sym.Java_com_coolapk_market_util_AuthUtils_getAS
|      |    0x000024b6      8b95b4feffff   mov edx, dword [var_14ch]
|      |    0x000024bc      89542404       mov dword [var_4h], edx
|      |    0x000024c0      8b9554feffff   mov edx, dword [var_1ach]
|      |    0x000024c6      891424         mov dword [esp], edx
|      |    0x000024c9      ffd0           call eax
|      |    0x000024cb      90             nop
|      |    ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1eff)
|      `--> 0x000024cc      8ba540feffff   mov esp, dword [var_1c0h]     ; Return
|           0x000024d2      8b93fcffffff   mov edx, dword [ebx - 4]
|           0x000024d8      8b4de4         mov ecx, dword [var_1ch]
|           0x000024db      8b12           mov edx, dword [edx]
|           0x000024dd      39d1           cmp ecx, edx
|       ,=< 0x000024df      7405           je 0x24e6
|       |   0x000024e1      e89ae1ffff     call sym.__stack_chk_fail_local
|       |   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x24df)
|       `-> 0x000024e6      8d65f4         lea esp, [var_ch_2]
|           0x000024e9      5b             pop ebx
|           0x000024ea      5e             pop esi
|           0x000024eb      5f             pop edi
|           0x000024ec      5d             pop ebp
\           0x000024ed      c3             ret
 */
// Main business logic
jstring Java_com_coolapk_market_util_AuthUtils_getAS(JNIEnv *env, jobject obj, jobject entryObject, jstring jstr) {
    /**
    |           ; var int var_ddh @ ebp-0xdd    ; char *h
    |           ; var int var_120h @ ebp-0x120
    |           ; var int var_122h @ ebp-0x122  ; "et"
    |           ; var int var_126h @ ebp-0x126  ; "mark"
    |           ; var int var_12ah @ ebp-0x12a  ; "apk."
    |           ; var int var_12eh @ ebp-0x12e  ; "cool"
    |           ; var int var_132h @ ebp-0x132  ; *char = com.coolapk.market\00
    |           ; var int var_19ch @ ebp-0x19c  ; *char nPackageName = getPackageName()
    |           ; var int var_1a0h @ ebp-0x1a0  ; jstring packageName
    |           ; var int var_1a4h @ ebp-0x1a4  ; jmethodID midGetPackageName
    |           ; var int var_1a8h @ ebp-0x1a8  ; jclass android_content_Context
    |           ; var int var_1c0h @ ebp-0x1c0  ; security_cookie
    |           ; var int var_1ch @ ebp-0x1c
    |           ; var int var_1b8h @ ebp-0x1b8  ; str
    |           ; arg int arg_14h @ ebp+0x14    ; jstring str ~JNIEnv *env
    |           ; var int var_1b4h @ ebp-0x1b4  ; obj
    |           ; arg int arg_10h @ ebp+0x10    ; jobject obj
    |           ; var int var_1b0h @ ebp-0x1b0  ; entryObject
    |           ; arg int arg_ch @ ebp+0xc      ; jobject entryObject
    |           ; var int var_1ach @ ebp-0x1ac  ; JNIEnv *env ~jstr
    |           ; arg int arg_8h @ ebp+0x8      ; env ~jstring jstr
    |           ; var int var_4h @ esp+0x4
    |           ; var int var_8h @ esp+0x8
    |           ; var int var_ch @ esp+0xc
    |           ; arg int arg_10h_2 @ esp+0x10
    |           0x00001d2a      55             push ebp
    |           0x00001d2b      89e5           mov ebp, esp
    |           0x00001d2d      57             push edi
    |           0x00001d2e      56             push esi
    |           0x00001d2f      53             push ebx
    |           0x00001d30      8da42434feff.  lea esp, [esp - 0x1cc]
    |           0x00001d37      e864e9ffff     call sym.__x86.get_pc_thunk.bx
    |           0x00001d3c      81c390220000   add ebx, 0x2290
    |           0x00001d42      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0 ; env
    |           0x00001d45      898554feffff   mov dword [var_1ach], eax   ; env
    |           0x00001d4b      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
    |           0x00001d4e      898550feffff   mov dword [var_1b0h], eax
    |           0x00001d54      8b4510         mov eax, dword [arg_10h]    ; [0x10:4]=0x30003
    |           0x00001d57      89854cfeffff   mov dword [var_1b4h], eax
    |           0x00001d5d      8b4514         mov eax, dword [arg_14h]    ; [0x14:4]=1
    |           0x00001d60      898548feffff   mov dword [var_1b8h], eax
    |           0x00001d66      8b83fcffffff   mov eax, dword [ebx - 4]    ; sp[-1]
    |           0x00001d6c      8b00           mov eax, dword [eax]
    |           0x00001d6e      8945e4         mov dword [var_1ch], eax
    |           0x00001d71      89e0           mov eax, esp
    |           0x00001d73      898540feffff   mov dword [var_1c0h], eax
    |           0x00001d79      8b8554feffff   mov eax, dword [var_1ach]   ; env
    |           0x00001d7f      8b00           mov eax, dword [eax]        : ax = *env
    |           0x00001d81      8b407c         mov eax, dword [eax + 0x7c] ; [0x7c:4]=0x3ebc segment.GNU_RELRO ; '|' ; jclass (*GetObjectClass)(JNIEnv *, jobject); (+0x7c)
    |           0x00001d84      8b954cfeffff   mov edx, dword [var_1b4h]
    |           0x00001d8a      89542404       mov dword [var_4h], edx     ; arg2 = obj
    |           0x00001d8e      8b9554feffff   mov edx, dword [var_1ach]
    |           0x00001d94      891424         mov dword [esp], edx        ; arg1 = env
    |           0x00001d97      ffd0           call eax                    ; GetObjectClass(env, obj);
    |           0x00001d99      898558feffff   mov dword [var_1a8h], eax   ; Line 55 ~= android_content_Context = env->GetObjectClass(env, obj);
    |           0x00001d9f      8b8554feffff   mov eax, dword [var_1ach]
    |           0x00001da5      8b00           mov eax, dword [eax]
    |           0x00001da7      8b8084000000   mov eax, dword [eax + 0x84] ; [0x84:4]=328 ; jmethodID (*GetMethodID)(JNIEnv *, jclass, char *name, char *sig); (+0x84)
    |           0x00001dad      8d937de6ffff   lea edx, [ebx - 0x1983]                    ; sig:GetMethodID = ()Ljava/lang/String; (offset:getPackageName + 21)
    |           0x00001db3      8954240c       mov dword [var_ch], edx
    |           0x00001db7      8d9392e6ffff   lea edx, [ebx - 0x196e]                    ; name:GetMethodID = getPackageName
    |           0x00001dbd      89542408       mov dword [var_8h], edx
    |           0x00001dc1      8b9558feffff   mov edx, dword [var_1a8h]
    |           0x00001dc7      89542404       mov dword [var_4h], edx                    ; arg2 = android_content_Context
    |           0x00001dcb      8b9554feffff   mov edx, dword [var_1ach]
    |           0x00001dd1      891424         mov dword [esp], edx
    |           0x00001dd4      ffd0           call eax                                   ; env->GetMethodID(env, android_content_Context:arg2, name:[ebx - 0x196e], sig:[ebx - 0x1983])
    |           0x00001dd6      89855cfeffff   mov dword [var_1a4h], eax    ; Line 56 ~= midGetPackageName = env->GetMethodID(env, android_content_Context, "getPackageName", "()Ljava/lang/String;");
    |           0x00001ddc      8b8554feffff   mov eax, dword [var_1ach]
    |           0x00001de2      8b00           mov eax, dword [eax]
    |           0x00001de4      8b8088000000   mov eax, dword [eax + 0x88] ; [0x88:4]=328 ; jobject (*CallObjectMethod)(JNIEnv *, jobject, jmethodID); (+0x88)
    |           0x00001dea      8b955cfeffff   mov edx, dword [var_1a4h]
    |           0x00001df0      89542408       mov dword [var_8h], edx     ; arg3 = midGetPackageName
    |           0x00001df4      8b954cfeffff   mov edx, dword [var_1b4h]
    |           0x00001dfa      89542404       mov dword [var_4h], edx     ; arg2 = obj
    |           0x00001dfe      8b9554feffff   mov edx, dword [var_1ach]
    |           0x00001e04      891424         mov dword [esp], edx        ; arg1 = env
    |           0x00001e07      ffd0           call eax                    ; CallObjectMethod(env, obj, midGetPackageName)
    |           0x00001e09      898560feffff   mov dword [var_1a0h], eax   ; Line 60 ~= packageName = env->CallObjectMethod(env, obj, midGetPackageName);
    |           0x00001e0f      8b8554feffff   mov eax, dword [var_1ach]
    |           0x00001e15      8b00           mov eax, dword [eax]
    |           0x00001e17      8b80a4020000   mov eax, dword [eax + 0x2a4] ; [0x2a4:4]=0x80012 ; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)
    |           0x00001e1d      c74424080000.  mov dword [var_8h], 0        ; arg3 = false
    |           0x00001e25      8b9560feffff   mov edx, dword [var_1a0h]
    |           0x00001e2b      89542404       mov dword [var_4h], edx      ; arg2 = packageName
    |           0x00001e2f      8b9554feffff   mov edx, dword [var_1ach]
    |           0x00001e35      891424         mov dword [esp], edx         ; arg1 = env
    |           0x00001e38      ffd0           call eax                     ; GetStringUTFChars(env, packageName, false)
    |           0x00001e3a      898564feffff   mov dword [var_19ch], eax    ; Line 61 ~= nPackageName = env->GetStringUTFChars(env, packageName, 0);
    |           0x00001e40      c785cefeffff.  mov dword [var_132h], 0x2e6d6f63 ; 'com.'
    |           0x00001e4a      c785d2feffff.  mov dword [var_12eh], 0x6c6f6f63 ; 'cool'
    |           0x00001e54      c785d6feffff.  mov dword [var_12ah], 0x2e6b7061 ; 'apk.'
    |           0x00001e5e      c785dafeffff.  mov dword [var_126h], 0x6b72616d ; 'mark'
    |           0x00001e68      66c785defeff.  mov word [var_122h], 0x7465 ; 'et'
    |           0x00001e71      c685e0feffff.  mov byte [var_120h], 0
    |           0x00001e78      8d85cefeffff   lea eax, [var_132h]
    |           0x00001e7e      89442404       mov dword [var_4h], eax     ; arg2 = "com.coolapk.market" ; （迫真包名校验）
    |           0x00001e82      8b8564feffff   mov eax, dword [var_19ch]
    |           0x00001e88      890424         mov dword [esp], eax        ; arg1 = packageName
    |           0x00001e8b      e830e7ffff     call sym.imp.strcmp         ; int strcmp(const char *s1, const char *s2)
    |           0x00001e90      85c0           test eax, eax               ; Line 62 ~= if (strcmp(packageName, "com.coolapk.market") != 0) {
    |       ,=< 0x00001e92      7470           je 0x1f04                   ; jump if equals (zero)
    |       |   0x00001e94      8b8554feffff   mov eax, dword [var_1ach]
    |       |   0x00001e9a      8b00           mov eax, dword [eax]
    |       |   0x00001e9c      8b405c         mov eax, dword [eax + 0x5c] ; [0x5c:4]=0 ; '\' ; void (*DeleteLocalRef)(JNIEnv *, jobject); (+0x5c)
    |       |   0x00001e9f      8b9558feffff   mov edx, dword [var_1a8h]
    |       |   0x00001ea5      89542404       mov dword [var_4h], edx     ; arg2 = android_content_Context
    |       |   0x00001ea9      8b9554feffff   mov edx, dword [var_1ach]
    |       |   0x00001eaf      891424         mov dword [esp], edx        ; arg1 = env
    |       |   0x00001eb2      ffd0           call eax                    ; DeleteLocalRef(env, arg2) ; Line ??? ~= env->DeleteLocalRef(env, android_content_Context);
    |       |   0x00001eb4      8b8554feffff   mov eax, dword [var_1ach]
    |       |   0x00001eba      8b00           mov eax, dword [eax]
    |       |   0x00001ebc      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172 ; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)
    |       |   0x00001ec2      8b9564feffff   mov edx, dword [var_19ch]
    |       |   0x00001ec8      89542408       mov dword [var_8h], edx      ; arg3 = packageNameChars (nPackageName)
    |       |   0x00001ecc      8b9560feffff   mov edx, dword [var_1a0h]
    |       |   0x00001ed2      89542404       mov dword [var_4h], edx      ; arg2 = packageName
    |       |   0x00001ed6      8b9554feffff   mov edx, dword [var_1ach]
    |       |   0x00001edc      891424         mov dword [esp], edx
    |       |   0x00001edf      ffd0           call eax                     ; ReleaseStringUTFChars(env, packageName, nPackageName) ; Line ??? ~= env->ReleaseStringUTFChars(env, packageName, nPackageName);
    |       |   0x00001ee1      8b8554feffff   mov eax, dword [var_1ach]
    |       |   0x00001ee7      8b00           mov eax, dword [eax]
    |       |   0x00001ee9      8b4054         mov eax, dword [eax + 0x54]  ; [0x54:4]=1 ; 'T' ; jobject (*NewGlobalRef)(JNIEnv *, jobject); (+0x54)
    |       |   0x00001eec      c74424040000.  mov dword [var_4h], 0        ; C NULL
    |       |   0x00001ef4      8b9554feffff   mov edx, dword [var_1ach]
    |       |   0x00001efa      891424         mov dword [esp], edx         ; env
    |       |   0x00001efd      ffd0           call eax                     ; NewGlobalRef(env, NULL)
    |      ,==< 0x00001eff      e9c8050000     jmp 0x24cc                   ; return ; Line ??? ~= return env->NewGlobalRef(env, NULL);
    |      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1e92)
     */
    jclass android_content_Context; // L55
    jstring packageName;  // L60
    jmethodID midGetPackageName;  // L56
    char *nPackageName;  // L61
    char cp[] = "com.coolapk.market"; // L63

    android_content_Context = (*env)->GetObjectClass(env, obj); // Line 55
    midGetPackageName = (*env)->GetMethodID(env, android_content_Context, "getPackageName", "()Ljava/lang/String;"); // Line 56

    packageName = (*env)->CallObjectMethod(env, obj, midGetPackageName); // Line 60
    nPackageName = (*env)->GetStringUTFChars(env, packageName, 0); // Line 61

    if (strcmp(packageName, /* variable cp (coolmarket packageName) */ cp) != 0) { // Line 63
        (*env)->DeleteLocalRef(env, android_content_Context);

        (*env)->ReleaseStringUTFChars(env, packageName, nPackageName);

        return (*env)->NewGlobalRef(env, NULL);
    }

    /**
    |      |`-> 0x00001f04      8d8523ffffff   lea eax, [var_ddh]           ; } // with a new soul~
    |      |    0x00001f0a      8d93a8e6ffff   lea edx, [ebx - 0x1958]      ; [ebx - 0x1968] (offset @ .rodata, offset:getPackageName - 22) = ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO
    |      |    0x00001f10      c78544feffff.  mov dword [var_1bch], 0xc1   ; = 193, sizeof("ld...") = 193
    |      |    0x00001f1a      89c1           mov ecx, eax                 ; vddh
    |      |    0x00001f1c      83e101         and ecx, 1                   ; vddh & true
    |      |    0x00001f1f      85c9           test ecx, ecx                ; if (vddh != NULL) {
    |      |,=< 0x00001f21      7412           jz 0x1f35                    ; it's true first time
    |      ||   0x00001f23      0fb60a         movzx ecx, byte [edx]        ; offset .rodata.ld...
    |      ||   0x00001f26      8808           mov byte [eax], cl           ; (char) ax = ldTM[i] ; cp[0] = ldTM[0]
    |      ||   0x00001f28      8d4001         lea eax, [eax + 1]           ; ax = cp[1]
    |      ||   0x00001f2b      8d5201         lea edx, [edx + 1]           ; dx = h[1]
    |      ||   0x00001f2e      83ad44feffff.  sub dword [var_1bch], 1      ; iter--
    |      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f21)
    |      |`-> 0x00001f35      89c1           mov ecx, eax                 ; }
    |      |    0x00001f37      83e102         and ecx, 2                   ; if (cp[1] & 2)
    |      |    0x00001f3a      85c9           test ecx, ecx
    |      |,=< 0x00001f3c      7413           jz 0x1f51
    |      ||   0x00001f3e      0fb70a         movzx ecx, word [edx]        ; cx = h[1]
    |      ||   0x00001f41      668908         mov word [eax], cx           ; cp[1] = h[1]
    |      ||   0x00001f44      8d4002         lea eax, [eax + 2]           ; cp += 2
    |      ||   0x00001f47      8d5202         lea edx, [edx + 2]           ; hp += 2
    |      ||   0x00001f4a      83ad44feffff.  sub dword [var_1bch], 2      ; iter -= 2
    |      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f3c)
    |      |`-> 0x00001f51      8b8d44feffff   mov ecx, dword [var_1bch]    ; cx = iter
    |      |    0x00001f57      c1e902         shr ecx, 2                   ; cx /= 4
    |      |    0x00001f5a      89c7           mov edi, eax                 ; cp
    |      |    0x00001f5c      89d6           mov esi, edx                 ; h
    |      |    0x00001f5e      f3a5           rep movsd dword es:[edi], dword ptr [esi]
    |      |    0x00001f60      89f2           mov edx, esi                 ; h
    |      |    0x00001f62      89f8           mov eax, edi                 ; cp
    |      |    0x00001f64      b900000000     mov ecx, 0
    |      |    0x00001f69      8bb544feffff   mov esi, dword [var_1bch]    ; iter
    |      |    0x00001f6f      83e602         and esi, 2                   ; iter & 2
    |      |    0x00001f72      85f6           test esi, esi
    |      |,=< 0x00001f74      740b           jz 0x1f81                    ; if (iter & 2 != 0) {
    |      ||   0x00001f76      0fb7340a       movzx esi, word [edx + ecx]  ; si = h[0]
    |      ||   0x00001f7a      66893408       mov word [eax + ecx], si     ; cp[0] = si
    |      ||   0x00001f7e      83c102         add ecx, 2                   ; cx += 2
    |      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f74) ; }
    |      |`-> 0x00001f81      8bb544feffff   mov esi, dword [var_1bch]
    |      |    0x00001f87      83e601         and esi, 1                   ; if (iter & 1)
    |      |    0x00001f8a      85f6           test esi, esi
    |      |,=< 0x00001f8c      7407           jz 0x1f95
    |      ||   0x00001f8e      0fb6140a       movzx edx, byte [edx + ecx]  ; c = h[cx]
    |      ||   0x00001f92      881408         mov byte [eax + ecx], dl     ; cp[cx] = c
    |      ||   ; CODE XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f8c)

    |      |`-> 0x00001f95      8d8523ffffff   lea eax, [h]
    |      |    0x00001f9b      890424         mov dword [esp], eax        ; arg1 = vddh
    |      |    0x00001f9e      e8a4fbffff     call sym.r                  ; (inout) reverse a string
    |      |    0x00001fa3      8d8523ffffff   lea eax, [h]
    |      |    0x00001fa9      890424         mov dword [esp], eax        ; arg1 = vddh
    |      |    0x00001fac      e8f3e6ffff     call sym.BDL                ; Base64 decode length(char *codebuf)
    |      |    0x00001fb1      898568feffff   mov dword [h2_len], eax     ; v198 = BDL(h)
    |      |    0x00001fb7      8b8568feffff   mov eax, dword [h2_len]     ; ax = h2_len
    |      |    0x00001fbd      8d50ff         lea edx, [eax - 1]          ; [h2_len - 1]
    |      |    0x00001fc0      89956cfeffff   mov dword [var_194h], edx   ; v194 = h2_len - 1
    |      |    0x00001fc6      89c2           mov edx, eax                ; dx = h2_len
    |      |    0x00001fc8      b810000000     mov eax, 0x10               ; ax = 16
    |      |    0x00001fcd      83e801         sub eax, 1                  ; ax = 15
    |      |    0x00001fd0      01d0           add eax, edx                ; ax = 15 + h2_len
    |      |    0x00001fd2      bf10000000     mov edi, 0x10               ; di = 16
    |      |    0x00001fd7      ba00000000     mov edx, 0                  ; dx = 0
    |      |    0x00001fdc      f7f7           div edi                     ;
    |      |    0x00001fde      6bc010         imul eax, eax, 0x10
    |      |    0x00001fe1      29c4           sub esp, eax                ; dynamic stack allocation
    |      |    0x00001fe3      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x00001fe7      83c000         add eax, 0
    |      |    0x00001fea      898570feffff   mov dword [h2], eax         ; h2 = {dynamic stack allocation: h2_len}
    |      |    0x00001ff0      8b8570feffff   mov eax, dword [h2]
    |      |    0x00001ff6      8d9523ffffff   lea edx, [h]
    |      |    0x00001ffc      89542404       mov dword [var_4h], edx     ; arg2 = var_ddh
    |      |    0x00002000      890424         mov dword [esp], eax        ; arg1 = h2
    |      |    0x00002003      e8bcfbffff     call sym.bd                 ; Base64 decode(char *out, const char *codestr)
    |      |    0x00002008      8b8570feffff   mov eax, dword [h2]
    |      |    0x0000200e      890424         mov dword [esp], eax        ; arg1 = var_190h
    |      |    0x00002011      e831fbffff     call sym.r                  ; reverse a char buffer
     */

    // With a new soul
    char h[193] = "ldTM3cTZiFTMhFzMlFWN2cjMjVDNzQWYxYTOwU2MwIDZHljcadFN2wUe5omYyATdZJTO2J2RGdXY5VDdZhlSypFWRZXW6l1MadVWx8EVRpnT6dGMaRUQ14keVdnWH5UbZ1WS61EVBlXTHl1dZdVSvcDZzI2YmVWMjF2NwAjZkN2YmVTY4UTO1YWO4Y2NwQGO";   // [var_ddh]  // salted base64 // L73
    //char mt[];

    r(h); // reverse
    int h2_len = BDL(h); // L80

    char h2[h2_len];     // [var_190h] // decode output // L81

    bd(h2, h);

    r(h2); // reverse

    /**
    |      |    0x00002016      8b8570feffff   mov eax, dword [var_190h]
    |      |    0x0000201c      890424         mov dword [esp], eax
    |      |    0x0000201f      e87ce5ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
    |      |    0x00002024      83e840         sub eax, 0x40               ; '@'
    |      |    0x00002027      898574feffff   mov dword [var_18ch], eax   ; v18c(h3_len) = strlen(h2) - 64
    |      |    0x0000202d      8b8574feffff   mov eax, dword [var_18ch]   ; ax = v18c
    |      |    0x00002033      83c001         add eax, 1                  ; ax = strlen(h2) - 63 // skip NUL
    |      |    0x00002036      8d50ff         lea edx, [eax - 1]          ; dx =
    |      |    0x00002039      899578feffff   mov dword [var_188h], edx
    |      |    0x0000203f      89c2           mov edx, eax
    |      |    0x00002041      b810000000     mov eax, 0x10
    |      |    0x00002046      83e801         sub eax, 1
    |      |    0x00002049      01d0           add eax, edx
    |      |    0x0000204b      bf10000000     mov edi, 0x10               ; 太长不看，差评 GCC 4.9 （As a reverse engineering lover）
    |      |    0x00002050      ba00000000     mov edx, 0
    |      |    0x00002055      f7f7           div edi
    |      |    0x00002057      6bc010         imul eax, eax, 0x10
    |      |    0x0000205a      29c4           sub esp, eax                ; dynamic allocation for h3:h3_len
    |      |    0x0000205c      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x00002060      83c000         add eax, 0
    |      |    0x00002063      89857cfeffff   mov dword [var_184h], eax
    |      |    0x00002069      8b9574feffff   mov edx, dword [var_18ch]   ; h3_len
    |      |    0x0000206f      8b8570feffff   mov eax, dword [var_190h]   ; h2
    |      |    0x00002075      8d4820         lea ecx, [eax + 0x20]       ; "l\x8c"
    |      |    0x00002078      8b857cfeffff   mov eax, dword [var_184h]
    |      |    0x0000207e      89542408       mov dword [var_8h], edx     ; arg3 = h3_len
    |      |    0x00002082      894c2404       mov dword [var_4h], ecx     ; arg2 = h2 + 0x20
    |      |    0x00002086      890424         mov dword [esp], eax        ; arg1 = h2
    |      |    0x00002089      e8f2e4ffff     call sym.imp.memcpy         ; void *memcpy(void *s1, const void *s2, size_t n)
    |      |    0x0000208e      8b957cfeffff   mov edx, dword [var_184h]
    |      |    0x00002094      8b8574feffff   mov eax, dword [var_18ch]
    |      |    0x0000209a      01d0           add eax, edx
    |      |    0x0000209c      c60000         mov byte [eax], 0
    |      |    0x0000209f      8b857cfeffff   mov eax, dword [var_184h]
    |      |    0x000020a5      890424         mov dword [esp], eax        ; h3 (dynamic allocation)
    |      |    0x000020a8      e8f7e5ffff     call sym.BDL                ; BDL(h3)
    |      |    0x000020ad      898580feffff   mov dword [var_180h], eax   ; v180(h3_len) = ^
    |      |    0x000020b3      8b8580feffff   mov eax, dword [var_180h]
    |      |    0x000020b9      8d50ff         lea edx, [eax - 1]
    |      |    0x000020bc      899584feffff   mov dword [var_17ch], edx
    |      |    0x000020c2      89c2           mov edx, eax
    |      |    0x000020c4      b810000000     mov eax, 0x10
    |      |    0x000020c9      83e801         sub eax, 1
    |      |    0x000020cc      01d0           add eax, edx
    |      |    0x000020ce      bf10000000     mov edi, 0x10
    |      |    0x000020d3      ba00000000     mov edx, 0
    |      |    0x000020d8      f7f7           div edi
    |      |    0x000020da      6bc010         imul eax, eax, 0x10
    |      |    0x000020dd      29c4           sub esp, eax                ; dynamic allocation for h4:h4_len
    |      |    0x000020df      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x000020e3      83c000         add eax, 0
    |      |    0x000020e6      898588feffff   mov dword [var_178h], eax   ; h4
    |      |    0x000020ec      8b957cfeffff   mov edx, dword [var_184h]    ; local_in  ; h2
    |      |    0x000020f2      8b8588feffff   mov eax, dword [var_178h]    ; local_out ; h3
    |      |    0x000020f8      89542404       mov dword [var_4h], edx      ; arg2 = dx ; arg2 = h3
    |      |    0x000020fc      890424         mov dword [esp], eax         ; ax = out  ; arg1 = h4
    |      |    0x000020ff      e8c0faffff     call sym.bd                  ; bd(out, base64)
    |      |    0x00002104      8b8554feffff   mov eax, dword [var_1ach]
    |      |    0x0000210a      8b00           mov eax, dword [eax]         ; (*env)
    |      |    0x0000210c      8b80a4020000   mov eax, dword [eax + 0x2a4] ; [0x2a4:4]=0x80012 ; char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *); (+0x2a4)
    |      |    0x00002112      c74424080000.  mov dword [var_8h], 0        ; arg3 = false
    |      |    0x0000211a      8b9548feffff   mov edx, dword [var_1b8h]    ; jstr ~arg2 = offset h3[64]
    |      |    0x00002120      89542404       mov dword [var_4h], edx
    |      |    0x00002124      8b9554feffff   mov edx, dword [var_1ach]    ; env
    |      |    0x0000212a      891424         mov dword [esp], edx
    |      |    0x0000212d      ffd0           call eax
    |      |    0x0000212f      89858cfeffff   mov dword [var_174h], eax   ; v174 = jstr.utfChars
    |      |    0x00002135      c70424000000.  mov dword [esp], 0          ; arg1 = NULL
    |      |    0x0000213c      e88fe4ffff     call sym.imp.time           ; time_t time(time_t *timer)
    |      |    0x00002141      898590feffff   mov dword [var_170h], eax
    |      |    0x00002147      8b8590feffff   mov eax, dword [var_170h]
    |      |    0x0000214d      89442408       mov dword [var_8h], eax     ; arg3 = time(NULL)
    |      |    0x00002151      8d83a1e6ffff   lea eax, [ebx - 0x195f]     ; offset:getPackageName(0x196e) - 15
    |      |    0x00002157      89442404       mov dword [var_4h], eax     ; arg2 = .rodata: "%d"
    |      |    0x0000215b      8d85c3feffff   lea eax, [var_13dh]
    |      |    0x00002161      890424         mov dword [esp], eax        ; arg1 = char h4[]
    |      |    0x00002164      e847e4ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
     */
    printf("%s\n", h2);

    int n = strlen(h2) - 0x40;
    memcpy(h2, h2 + 0x20, n);

    printf("%s\n", h2);

    int h3_len = BDL(h2);
    char h3[h3_len];

    bd(h3, h2);
    printf("%s\n", h3);

    int tl = time(NULL); // L115
    char t[128]; // L116

    sprintf(t, "%d", (int) tl);

    printf("t: %s\n", t);

    /**
    |      |    0x00002169      8b8590feffff   mov eax, dword [var_170h]   ; time
    |      |    0x0000216f      89442408       mov dword [var_8h], eax     ; arg3 = time
    |      |    0x00002173      8d83a4e6ffff   lea eax, [ebx - 0x195c]     ; offset:getPackageName(0x196e) - 18
    |      |    0x00002179      89442404       mov dword [var_4h], eax     ; arg2 = .rodata: "%x"
    |      |    0x0000217d      8d85b9feffff   lea eax, [var_147h]         ; char ht[]
    |      |    0x00002183      890424         mov dword [esp], eax
    |      |    0x00002186      e825e4ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
    |      |    0x0000218b      8d85c3feffff   lea eax, [var_13dh]
    |      |    0x00002191      89442404       mov dword [var_4h], eax     ; arg2 = t
    |      |    0x00002195      8d85e1feffff   lea eax, [var_11fh]         ; arg1 = src (mt)
    |      |    0x0000219b      890424         mov dword [esp], eax
    |      |    0x0000219e      e84dfaffff     call sym.me                 ; me(mt, t)
    |      |    0x000021a3      8b8588feffff   mov eax, dword [var_178h]   ; h3
    |      |    0x000021a9      890424         mov dword [esp], eax
    |      |    0x000021ac      e8efe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
    |      |    0x000021b1      89c6           mov esi, eax                ; strlen(h3)
    |      |    0x000021b3      8b858cfeffff   mov eax, dword [var_174h]
    |      |    0x000021b9      890424         mov dword [esp], eax
    |      |    0x000021bc      e8dfe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
    |      |    0x000021c1      01c6           add esi, eax                ; strlen(uuidChars)
    |      |    0x000021c3      8b8564feffff   mov eax, dword [var_19ch]
    |      |    0x000021c9      890424         mov dword [esp], eax        ; packageNameChars
    |      |    0x000021cc      e8cfe3ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
    |      |    0x000021d1      01f0           add eax, esi
    |      |    0x000021d3      83c023         add eax, 0x23               ; '#'
    |      |    0x000021d6      898594feffff   mov dword [var_16ch], eax
    |      |    0x000021dc      8b8594feffff   mov eax, dword [var_16ch]
    |      |    0x000021e2      8d50ff         lea edx, [eax - 1]
    |      |    0x000021e5      899598feffff   mov dword [var_168h], edx
    |      |    0x000021eb      89c2           mov edx, eax
    |      |    0x000021ed      b810000000     mov eax, 0x10
    |      |    0x000021f2      83e801         sub eax, 1
    |      |    0x000021f5      01d0           add eax, edx
    |      |    0x000021f7      bf10000000     mov edi, 0x10
    |      |    0x000021fc      ba00000000     mov edx, 0
    |      |    0x00002201      f7f7           div edi
    |      |    0x00002203      6bc010         imul eax, eax, 0x10
    |      |    0x00002206      29c4           sub esp, eax                ; dynamic allocation for char h4[strlen(h3) + strlen(uuidChars) + strlen(packageNameChars)]
    |      |    0x00002208      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x0000220c      83c000         add eax, 0
    |      |    0x0000220f      89859cfeffff   mov dword [var_164h], eax   ; h4
    |      |    0x00002215      8b9588feffff   mov edx, dword [var_178h]
    |      |    0x0000221b      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x00002221      89542404       mov dword [var_4h], edx     ; h3
    |      |    0x00002225      890424         mov dword [esp], eax
    |      |    0x00002228      e8b3e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x0000222d      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x00002233      8d95e1feffff   lea edx, [var_11fh]         ; arg2 = mt
    |      |    0x00002239      89542404       mov dword [var_4h], edx
    |      |    0x0000223d      890424         mov dword [esp], eax
    |      |    0x00002240      e89be3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x00002245      8bb59cfeffff   mov esi, dword [var_164h]
    |      |    0x0000224b      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x00002251      b9ffffffff     mov ecx, 0xffffffff         ; -1
    |      |    0x00002256      89c2           mov edx, eax
    |      |    0x00002258      b800000000     mov eax, 0
    |      |    0x0000225d      89d7           mov edi, edx
    |      |    0x0000225f      f2ae           repne scasb al, byte es:[edi]
    |      |    0x00002261      89c8           mov eax, ecx
    |      |    0x00002263      f7d0           not eax                     ; ???? TODO: review this
    |      |    0x00002265      83e801         sub eax, 1
    |      |    0x00002268      01f0           add eax, esi
    |      |    0x0000226a      66c7002400     mov word [eax], 0x24        ; '$' ; [0x24:2]=0
    |      |    0x0000226f      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x00002275      8b958cfeffff   mov edx, dword [var_174h]   ; jstrChars
    |      |    0x0000227b      89542404       mov dword [var_4h], edx     ; arg2 = h3
    |      |    0x0000227f      890424         mov dword [esp], eax
    |      |    0x00002282      e859e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x00002287      8bb59cfeffff   mov esi, dword [var_164h]
    |      |    0x0000228d      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x00002293      b9ffffffff     mov ecx, 0xffffffff         ; -1
    |      |    0x00002298      89c2           mov edx, eax
    |      |    0x0000229a      b800000000     mov eax, 0
    |      |    0x0000229f      89d7           mov edi, edx
    |      |    0x000022a1      f2ae           repne scasb al, byte es:[edi]
    |      |    0x000022a3      89c8           mov eax, ecx                ; ???? TODO: review this
    |      |    0x000022a5      f7d0           not eax
    |      |    0x000022a7      83e801         sub eax, 1
    |      |    0x000022aa      01f0           add eax, esi
    |      |    0x000022ac      66c7002600     mov word [eax], 0x26        ; '&' ; [0x26:2]=0
    |      |    0x000022b1      8b859cfeffff   mov eax, dword [var_164h]
    |      |    0x000022b7      8b9564feffff   mov edx, dword [var_19ch]
    |      |    0x000022bd      89542404       mov dword [var_4h], edx     ; arg2 = packageNameChars
    |      |    0x000022c1      890424         mov dword [esp], eax        ; arg1 = h4
    |      |    0x000022c4      e817e3ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x000022c9      8b8594feffff   mov eax, dword [var_16ch]
    |      |    0x000022cf      890424         mov dword [esp], eax
    |      |    0x000022d2      e80ae6ffff     call sym.BEL                ; BEL(strlen(packageNameChars))
    |      |    0x000022d7      8985a0feffff   mov dword [var_160h], eax
    |      |    0x000022dd      8b85a0feffff   mov eax, dword [var_160h]
    |      |    0x000022e3      8d50ff         lea edx, [eax - 1]
    |      |    0x000022e6      8995a4feffff   mov dword [var_15ch], edx
    |      |    0x000022ec      89c2           mov edx, eax
    |      |    0x000022ee      b810000000     mov eax, 0x10
    |      |    0x000022f3      83e801         sub eax, 1
    |      |    0x000022f6      01d0           add eax, edx
    |      |    0x000022f8      bf10000000     mov edi, 0x10
    |      |    0x000022fd      ba00000000     mov edx, 0
    |      |    0x00002302      f7f7           div edi
    |      |    0x00002304      6bc010         imul eax, eax, 0x10
    |      |    0x00002307      29c4           sub esp, eax                ; dynamic allocation for package name base64 codebuffer
    |      |    0x00002309      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x0000230d      83c000         add eax, 0
    |      |    0x00002310      8985a8feffff   mov dword [var_158h], eax
    |      |    0x00002316      8b959cfeffff   mov edx, dword [var_164h]   ; h4
    |      |    0x0000231c      8b85a8feffff   mov eax, dword [var_158h]   ; base64 encode buffer
    |      |    0x00002322      89542404       mov dword [var_4h], edx
    |      |    0x00002326      890424         mov dword [esp], eax
    |      |    0x00002329      e8bbf9ffff     call sym.be                 ; be(v158, h4)
    |      |    0x0000232e      8b85a8feffff   mov eax, dword [var_158h]
    |      |    0x00002334      89442404       mov dword [var_4h], eax
    |      |    0x00002338      8d8502ffffff   lea eax, [var_feh]
    |      |    0x0000233e      890424         mov dword [esp], eax
    |      |    0x00002341      e8aaf8ffff     call sym.me                 ; me(fe, v158)
    |      |    0x00002346      8d8502ffffff   lea eax, [var_feh]
    |      |    0x0000234c      890424         mov dword [esp], eax
    |      |    0x0000234f      e84ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s) len fe
    |      |    0x00002354      89c6           mov esi, eax
    |      |    0x00002356      8b858cfeffff   mov eax, dword [var_174h]
    |      |    0x0000235c      890424         mov dword [esp], eax
    |      |    0x0000235f      e83ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s) len jstrChars
    |      |    0x00002364      01c6           add esi, eax
    |      |    0x00002366      8d85b9feffff   lea eax, [var_147h]
    |      |    0x0000236c      890424         mov dword [esp], eax
    |      |    0x0000236f      e82ce2ffff     call sym.imp.strlen         ; size_t strlen(const char *s) len ht
    |      |    0x00002374      01f0           add eax, esi
    |      |    0x00002376      83c002         add eax, 2
    |      |    0x00002379      8985acfeffff   mov dword [var_154h], eax
    |      |    0x0000237f      8b85acfeffff   mov eax, dword [var_154h]
    |      |    0x00002385      8d50ff         lea edx, [eax - 1]
    |      |    0x00002388      8995b0feffff   mov dword [var_150h], edx
    |      |    0x0000238e      89c2           mov edx, eax
    |      |    0x00002390      b810000000     mov eax, 0x10
    |      |    0x00002395      83e801         sub eax, 1
    |      |    0x00002398      01d0           add eax, edx
    |      |    0x0000239a      bf10000000     mov edi, 0x10
    |      |    0x0000239f      ba00000000     mov edx, 0
    |      |    0x000023a4      f7f7           div edi
    |      |    0x000023a6      6bc010         imul eax, eax, 0x10
    |      |    0x000023a9      29c4           sub esp, eax                ; finally, char fin[]
    |      |    0x000023ab      8d442410       lea eax, [arg_10h_2]        ; 0x10
    |      |    0x000023af      83c000         add eax, 0
    |      |    0x000023b2      8985b4feffff   mov dword [var_14ch], eax
    |      |    0x000023b8      8b85b4feffff   mov eax, dword [var_14ch]
    |      |    0x000023be      8d9502ffffff   lea edx, [var_feh]
    |      |    0x000023c4      89542404       mov dword [var_4h], edx     ; fe
    |      |    0x000023c8      890424         mov dword [esp], eax        ; fin
    |      |    0x000023cb      e810e2ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x000023d0      8b85b4feffff   mov eax, dword [var_14ch]
    |      |    0x000023d6      8b958cfeffff   mov edx, dword [var_174h]
    |      |    0x000023dc      89542404       mov dword [var_4h], edx     ; jstrChars
    |      |    0x000023e0      890424         mov dword [esp], eax        ; fin
    |      |    0x000023e3      e8f8e1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x000023e8      8bb5b4feffff   mov esi, dword [var_14ch]
    |      |    0x000023ee      8b85b4feffff   mov eax, dword [var_14ch]
    |      |    0x000023f4      b9ffffffff     mov ecx, 0xffffffff         ; -1
    |      |    0x000023f9      89c2           mov edx, eax
    |      |    ; DATA XREF from sym.bd (0x1bd1)
    |      |    0x000023fb      b800000000     mov eax, 0
    |      |    0x00002400      89d7           mov edi, edx
    |      |    0x00002402      f2ae           repne scasb al, byte es:[edi]
    |      |    0x00002404      89c8           mov eax, ecx                ; TODO: review this
    |      |    0x00002406      f7d0           not eax
    |      |    0x00002408      83e801         sub eax, 1
    |      |    0x0000240b      01f0           add eax, esi
    |      |    0x0000240d      66c7003078     mov word [eax], 0x7830      ; '0x' ; [0x7830:2]=0xffff
    |      |    0x00002412      c6400200       mov byte [eax + 2], 0       ; ax = "0x\00"
    |      |    0x00002416      8b85b4feffff   mov eax, dword [var_14ch]
    |      |    0x0000241c      8d95b9feffff   lea edx, [var_147h]
    |      |    0x00002422      89542404       mov dword [var_4h], edx     ; hex_time
    |      |    0x00002426      890424         mov dword [esp], eax        ; fin
    |      |    0x00002429      e8b2e1ffff     call sym.imp.strcat         ; char *strcat(char *s1, const char *s2)
    |      |    0x0000242e      8b8554feffff   mov eax, dword [var_1ach]
    |      |    0x00002434      8b00           mov eax, dword [eax]
    |      |    0x00002436      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172  ; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)
    |      |    0x0000243c      8b958cfeffff   mov edx, dword [var_174h]
    |      |    0x00002442      89542408       mov dword [var_8h], edx
    |      |    0x00002446      8b9548feffff   mov edx, dword [var_1b8h]
    |      |    0x0000244c      89542404       mov dword [var_4h], edx
    |      |    0x00002450      8b9554feffff   mov edx, dword [var_1ach]
    |      |    0x00002456      891424         mov dword [esp], edx
    |      |    0x00002459      ffd0           call eax
    |      |    0x0000245b      8b8554feffff   mov eax, dword [var_1ach]
    |      |    0x00002461      8b00           mov eax, dword [eax]
    |      |    0x00002463      8b405c         mov eax, dword [eax + 0x5c] ; [0x5c:4]=0 ; '\' ; void (*DeleteLocalRef)(JNIEnv *, jobject); (+0x5c)
    |      |    0x00002466      8b9558feffff   mov edx, dword [var_1a8h]
    |      |    0x0000246c      89542404       mov dword [var_4h], edx
    |      |    0x00002470      8b9554feffff   mov edx, dword [var_1ach]
    |      |    0x00002476      891424         mov dword [esp], edx
    |      |    0x00002479      ffd0           call eax
    |      |    0x0000247b      8b8554feffff   mov eax, dword [var_1ach]
    |      |    0x00002481      8b00           mov eax, dword [eax]
    |      |    0x00002483      8b80a8020000   mov eax, dword [eax + 0x2a8] ; [0x2a8:4]=172 ; void (*ReleaseStringUTFChars)(JNIEnv *, jstring, char *); (+0x2a8)
    |      |    0x00002489      8b9564feffff   mov edx, dword [var_19ch]
    |      |    0x0000248f      89542408       mov dword [var_8h], edx
    |      |    0x00002493      8b9560feffff   mov edx, dword [var_1a0h]
    |      |    0x00002499      89542404       mov dword [var_4h], edx
    |      |    0x0000249d      8b9554feffff   mov edx, dword [var_1ach]
    |      |    0x000024a3      891424         mov dword [esp], edx
    |      |    0x000024a6      ffd0           call eax                     ; (*env)->ReleaseStringUTFChars(env, packageName, nPackageName)
    |      |    0x000024a8      8b8554feffff   mov eax, dword [var_1ach]
    |      |    0x000024ae      8b00           mov eax, dword [eax]
    |      |    0x000024b0      8b809c020000   mov eax, dword [eax + sym.Java_com_coolapk_market_util_AuthUtils_getAS] ; [0x29c:4]=0x1d2a sym.Java_com_coolapk_market_util_AuthUtils_getAS ; jstring (*NewStringUTF)(JNIEnv *, char *); (+0x29c)
    |      |    0x000024b6      8b95b4feffff   mov edx, dword [var_14ch]    ; char*
    |      |    0x000024bc      89542404       mov dword [var_4h], edx
    |      |    0x000024c0      8b9554feffff   mov edx, dword [var_1ach]
    |      |    0x000024c6      891424         mov dword [esp], edx
    |      |    0x000024c9      ffd0           call eax                     ; (*env)->NewStringUTF(env, var_14ch)
     */

    char ht[256];
    sprintf(ht, "%x", tl);

    printf("ht: %s\n", ht);

    char mt[256];
    me(mt, t);

    printf("me(t): %s\n", mt);

    char *jstrb;

    jstrb = (*env)->GetStringUTFChars(env, jstr, 0);

    char packageNameChars[] = "com.coolapk.market";

    char h4[strlen(h3) + strlen(jstrb) + strlen(packageNameChars) + 256];
    strcat(h4, h3);
    strcat(h4, mt);

    strcat(h4, jstrb);
    strcat(h4, packageNameChars);

    printf("h4: %s\n", h4);

    int rr_len = BEL(strlen(packageNameChars));
    char rr[rr_len + 1];

    be(rr, h4);
    printf("rr:(%i): %s\n", rr_len, rr);

    // 瞎 :chicken: 分配
    char fe[512];
    me(fe, rr);

    printf("fe: %s\n", fe);

    int fe_len = strlen(fe);
    int jstr_len = strlen(jstr);

    char fin[fe_len + jstr_len + rr_len + 1];
    strcat(fin, fe);
    strcat(fin, jstr);
    strcat(fin, ht);


    printf("fin: %s\n", fin);

    (*env)->ReleaseStringUTFChars(env, jstr, jstrb);
    (*env)->DeleteLocalRef(env, android_content_Context);
    (*env)->ReleaseStringUTFChars(env, packageName, nPackageName);

    return (*env)->NewStringUTF(env, fin);
}

/**
/ (fcn) sym.bd 44
|   sym.bd (int arg_8h, int arg_ch, int arg_14h);
|           ; arg int arg_8h @ ebp+0x8
|           ; arg int arg_ch @ ebp+0xc
|           ; var int var_4h @ esp+0x4
|           ; arg int arg_14h @ esp+0x14
|           ; CALL XREFS from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x2003, 0x20ff)
|           0x00001bc4      55             push ebp                    ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:24
|           0x00001bc5      89e5           mov ebp, esp
|           0x00001bc7      53             push ebx
|           0x00001bc8      8d6424ec       lea esp, [esp - 0x14]
|           0x00001bcc      e8cfeaffff     call sym.__x86.get_pc_thunk.bx ; bx = [sp]
|           0x00001bd1      81c3fb230000   add ebx, 0x23fb
|           0x00001bd7      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0 ; ax = arg2
|           0x00001bda      89442404       mov dword [var_4h], eax     ; sp[1] = ax
|           0x00001bde      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0 ; ax = arg1
|           0x00001be1      890424         mov dword [esp], eax        ; sp[0] = ax
|           0x00001be4      e81bebffff     call sym.BD                 ; BD(sp)
|           0x00001be9      8d642414       lea esp, [arg_14h]          ; 0x14
|           0x00001bed      5b             pop ebx
|           0x00001bee      5d             pop ebp
\           0x00001bef      c3             ret
*/
// Base64 decode
void bd(char *out, const char *code_str) {
    BD(out, code_str); // BD(arg1, arg2)
}

/**
/ (fcn) sym.be 65
|   sym.be (int arg_8h_2, int arg_ch, int arg_8h, int arg_24h);
|           ; var int var_ch @ ebp-0xc
|           ; arg int arg_8h_2 @ ebp+0x8
|           ; arg int arg_ch @ ebp+0xc
|           ; var int var_4h @ esp+0x4
|           ; arg int arg_8h @ esp+0x8
|           ; arg int arg_24h @ esp+0x24
|           ; CALL XREF from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x2329)
|           0x00001ce9      55             push ebp
|           0x00001cea      89e5           mov ebp, esp
|           0x00001cec      53             push ebx
|           0x00001ced      8d6424dc       lea esp, [esp - 0x24]
|           0x00001cf1      e8aae9ffff     call sym.__x86.get_pc_thunk.bx
|           0x00001cf6      81c3d6220000   add ebx, 0x22d6
|           0x00001cfc      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
|           0x00001cff      890424         mov dword [esp], eax
|           0x00001d02      e899e8ffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|           0x00001d07      8945f4         mov dword [var_ch], eax
|           0x00001d0a      8b45f4         mov eax, dword [var_ch]     ; ax = arg2 = strlen(arg2)
|           0x00001d0d      89442408       mov dword [arg_8h], eax     ; esp:0x8 = arg2
|           0x00001d11      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0
|           0x00001d14      89442404       mov dword [var_4h], eax     ; esp:0x4 = arg2
|           0x00001d18      8b4508         mov eax, dword [arg_8h_2]   ; [0x8:4]=0
|           0x00001d1b      890424         mov dword [esp], eax        ; esp = arg1
|           0x00001d1e      e8e1ebffff     call sym.BE                 ; BE(esp, :0x4, :0x8) ; BE(arg1, arg2, strlen(arg2))
|           0x00001d23      8d642424       lea esp, [arg_24h]          ; 0x24 ; '$'
|           0x00001d27      5b             pop ebx
|           0x00001d28      5d             pop ebp
\           0x00001d29      c3             ret
 */
// Base64 encode
void be(char *dst, const char *src) {
    BE(dst, src, strlen(src)); // BE(arg1, arg2, strlen(arg2))
}

/**
/ (fcn) sym.me 249
|   sym.me (int arg_8h, int arg_ch, int arg_8h_2, int arg_d4h);
|           ; var int var_c0h @ ebp-0xc0
|           ; var int var_bch @ ebp-0xbc
|           ; var int var_b8h @ ebp-0xb8 ; int i
|           ; var int var_b4h @ ebp-0xb4 ; unsigned char digest[16]
|           ; var int var_a4h @ ebp-0xa4
|           ; var int var_ch @ ebp-0xc
|           ; arg int arg_8h @ ebp+0x8 ; char *dst
|           ; arg int arg_ch @ ebp+0xc ; char *src
|           ; var int var_4h @ esp+0x4 ; MD5_CTX context
|           ; arg int arg_8h_2 @ esp+0x8
|           ; arg int arg_d4h @ esp+0xd4
|           ; CALL XREFS from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x219e, 0x2341)
|           0x00001bf0      55             push ebp
|           0x00001bf1      89e5           mov ebp, esp
|           0x00001bf3      53             push ebx
|           0x00001bf4      8da4242cffff.  lea esp, [esp - 0xd4]
|           0x00001bfb      e8a0eaffff     call sym.__x86.get_pc_thunk.bx ; bx = [sp]
|           0x00001c00      81c3cc230000   add ebx, 0x23cc
|           0x00001c06      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0 ; ax = dst
|           0x00001c09      898544ffffff   mov dword [var_bch], eax    ; vbc = dst
|           0x00001c0f      8b450c         mov eax, dword [arg_ch]     ; [0xc:4]=0 ; ax = src
|           0x00001c12      898540ffffff   mov dword [var_c0h], eax    ; vc0 = src
|           0x00001c18      8b83fcffffff   mov eax, dword [ebx - 4]    ; ax = sp[-1]
|           0x00001c1e      8b00           mov eax, dword [eax]        ; ax = *sp[-1]
|           0x00001c20      8945f4         mov dword [var_ch], eax     ; vc = *sp[-1]
|           0x00001c23      8d855cffffff   lea eax, [var_a4h]          ; ax = va4 @ esp+0x4
|           0x00001c29      890424         mov dword [esp], eax        ; sp[0] = va4
|           0x00001c2c      e809fbffff     call sym.MI                 ; void MI(MD5_CTX *ctx) ;
|           0x00001c31      8b8540ffffff   mov eax, dword [var_c0h]    ; ax = src
|           0x00001c37      890424         mov dword [esp], eax        ; sp[0] = src
|           0x00001c3a      e861e9ffff     call sym.imp.strlen         ; size_t strlen(const char *s) ; ax = strlen(src)
|           0x00001c3f      89442408       mov dword [arg_8h_2], eax   ; arg3 = strlen(src)
|           0x00001c43      8b8540ffffff   mov eax, dword [var_c0h]    ; ax = vc0 ; src
|           0x00001c49      89442404       mov dword [var_4h], eax     ; v4 = src
|           0x00001c4d      8d855cffffff   lea eax, [var_a4h]          ; ax = va4 @ esp+0x4 ; ctx
|           0x00001c53      890424         mov dword [esp], eax        ; sp[0] = ctx
|           0x00001c56      e81ffbffff     call sym.MU                 ; void MU(MD5_CTX *ctx, const void *data, unsigned long size) ; MU(ctx @ va4, v4, arg3 @ arg_8h_2)
|           0x00001c5b      8d855cffffff   lea eax, [var_a4h]          ; ax = va4 ; ctx
|           0x00001c61      89442404       mov dword [var_4h], eax     ; v4 (sp[1]) = ctx
|           0x00001c65      8d854cffffff   lea eax, [var_b4h]          ; ax = vb4
|           0x00001c6b      890424         mov dword [esp], eax        ; sp[0] = vb4
|           0x00001c6e      e84bfcffff     call sym.MF                 ; void MF(unsigned char *result, MD5_CTX *ctx) ; MF(vb4 @ sp[0], v4 @ sp[1])
|           0x00001c73      c78548ffffff.  mov dword [var_b8h], 0      ; vb8 = 0
|       ,=< 0x00001c7d      eb43           jmp 0x1cc2
|       |   ; CODE XREF from sym.me (0x1cc9)                           while (vb8 <= 15)
|      .--> 0x00001c7f      8d954cffffff   lea edx, [var_b4h]          ; dx = vb4 @ ebp-0xb4
|      :|   0x00001c85      8b8548ffffff   mov eax, dword [var_b8h]    ; ax = 0
|      :|   0x00001c8b      01d0           add eax, edx                ; ax = vb4 + 0
|      :|   0x00001c8d      0fb600         movzx eax, byte [eax]       ; ax = (char) ax
|      :|   0x00001c90      0fb6c0         movzx eax, al               ; ax = (char) low_short(ax)
|      :|   0x00001c93      8b9548ffffff   mov edx, dword [var_b8h]    ; dx = 0
|      :|   0x00001c99      01d2           add edx, edx                ; dx *= 2
|      :|   0x00001c9b      89d1           mov ecx, edx                ; cx = dx = 0
|      :|   0x00001c9d      8b9544ffffff   mov edx, dword [var_bch]    ; dx = vbc
|      :|   0x00001ca3      01ca           add edx, ecx                ; dx += (cx) ;= 0
|      :|   0x00001ca5      89442408       mov dword [arg_8h_2], eax   ; arg3 = ax ; and sprintf call arg3
|      :|   0x00001ca9      8d8378e6ffff   lea eax, [ebx - 0x1988]     ; ax = [sp - 0x1988]
|      :|   0x00001caf      89442404       mov dword [var_4h], eax     ; src = ax
|      :|   0x00001cb3      891424         mov dword [esp], edx        ; sp[0] = dx ; str
|      :|   0x00001cb6      e8f5e8ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
|      :|   0x00001cbb      838548ffffff.  add dword [var_b8h], 1      ; vb8 += 1 ; 1
|      :|   ; CODE XREF from sym.me (0x1c7d)
|      :`-> 0x00001cc2      83bd48ffffff.  cmp dword [var_b8h], 0xf    ; vb8 <=> 15
|      `==< 0x00001cc9      7eb4           jle 0x1c7f                  ; jump taken for the first time (vb8 (0) <= 15) always 1
|           0x00001ccb      8b83fcffffff   mov eax, dword [ebx - 4]    ; end while ; ax = sp[-1]
|           0x00001cd1      8b55f4         mov edx, dword [var_ch]     ; dx = *sp[-1]
|           0x00001cd4      8b00           mov eax, dword [eax]        ; ax = *ax
|           0x00001cd6      39c2           cmp edx, eax                ; security cookie @ sp[-1]
|       ,=< 0x00001cd8      7405           je 0x1cdf                   ; check stack overflow
|       |   0x00001cda      e8a1e9ffff     call sym.__stack_chk_fail_local
|       |   ; CODE XREF from sym.me (0x1cd8)
|       `-> 0x00001cdf      8da424d40000.  lea esp, [arg_d4h]          ; 0xd4 ; fini
|           0x00001ce6      5b             pop ebx
|           0x00001ce7      5d             pop ebp
\           0x00001ce8      c3             ret
 */
// MD5 message digest
void me(char *dst, char *src) {
    unsigned char vb4[16];
    MD5_CTX ctx_va4;

    MI(&ctx_va4);

    MU(&ctx_va4, src, strlen(src));

    MF(vb4, &ctx_va4);

    int vb8 = 0;

    while (vb8 <= 15) {
        /**
        |       |   ; CODE XREF from sym.me (0x1cc9)                           while (vb8 <= 15)
        |      .--> 0x00001c7f      8d954cffffff   lea edx, [var_b4h]          ; dx = vb4 @ ebp-0xb4 ; dx = md5
        |      :|   0x00001c85      8b8548ffffff   mov eax, dword [var_b8h]    ; ax = 0              ; ax = i
        |      :|   0x00001c8b      01d0           add eax, edx                ; ax = vb4 + 0        ; ax = md5 + i
        |      :|   0x00001c8d      0fb600         movzx eax, byte [eax]       ; ax = (char) ax      ; ax = (char) *ax
        |      :|   0x00001c90      0fb6c0         movzx eax, al               ; ax = (char) low_short(ax)
        |      :|   0x00001c93      8b9548ffffff   mov edx, dword [var_b8h]    ; dx = 0              ; dx = i
        |      :|   0x00001c99      01d2           add edx, edx                ; dx *= 2             ; dx = i ** 2
        |      :|   0x00001c9b      89d1           mov ecx, edx                ; cx = dx = 0         ; cx = dx
        |      :|   0x00001c9d      8b9544ffffff   mov edx, dword [var_bch]    ; dx = vbc            ; dx = vbc ; dst
        |      :|   0x00001ca3      01ca           add edx, ecx                ; dx += (cx) ;= 0     ; dx += i ** 2
        |      :|   0x00001ca5      89442408       mov dword [arg_8h_2], eax   ; arg3 = ax ; and sprintf call arg3
        |      :|   0x00001ca9      8d8378e6ffff   lea eax, [ebx - 0x1988]     ; ax = [sp - 0x1988]  ; security cookie ; offset +26 from 0x196e (getPackageName)
        |      :|   0x00001caf      89442404       mov dword [var_4h], eax     ; src = ax            ; sp[1] ; old = ctx
        |      :|   0x00001cb3      891424         mov dword [esp], edx        ; sp[0] = dx ; str
        |      :|   0x00001cb6      e8f5e8ffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
        |      :|   0x00001cbb      838548ffffff.  add dword [var_b8h], 1      ; vb8 += 1 ; 1
        |      :|   ; CODE XREF from sym.me (0x1c7d)
         */
        unsigned char tmp = vb4[vb8];

        char *str = dst + (vb8 * 2);
        sprintf(str, "%02x", tmp); // radare2 str.02x

        vb8++;
    }

    // check security cookie
}

/**
/ (fcn) sym.r 125
|   sym.r (int arg_8h, int arg_24h);
|           ; var int var_18h @ ebp-0x18 ; int i
|           ; var int var_14h @ ebp-0x14 ; int j
|           ; var int var_10h @ ebp-0x10 ; length @ line 15
|           ; var int var_ch @ ebp-0xc   ; int c ; low_addr -> char
|           ; arg int arg_8h @ ebp+0x8   ; *char @ line 13
|           ; arg int arg_24h @ esp+0x24
|           ; CALL XREFS from sym.Java_com_coolapk_market_util_AuthUtils_getAS (0x1f9e, 0x2011)
|           0x00001b47      55             push ebp                    ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:14
|           0x00001b48      89e5           mov ebp, esp
|           0x00001b4a      53             push ebx
|           0x00001b4b      8d6424dc       lea esp, [esp - 0x24]
|           0x00001b4f      e84cebffff     call sym.__x86.get_pc_thunk.bx
|           0x00001b54      81c378240000   add ebx, 0x2478             ; 'x$'
|           0x00001b5a      8b4508         mov eax, dword [arg_8h]     ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:15 ; [0x8:4]=0
|           0x00001b5d      890424         mov dword [esp], eax
|           0x00001b60      e83beaffff     call sym.imp.strlen         ; size_t strlen(const char *s)
|           0x00001b65      8945f0         mov dword [var_10h], eax
|           0x00001b68      c745e8000000.  mov dword [var_18h], 0      ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:18
|           0x00001b6f      8b45f0         mov eax, dword [var_10h]
|           0x00001b72      83e801         sub eax, 1
|           0x00001b75      8945ec         mov dword [var_14h], eax
|       ,=< 0x00001b78      eb3b           jmp 0x1bb5
|       |   ; CODE XREF from sym.r (0x1bbb)
|      .--> 0x00001b7a      8b55e8         mov edx, dword [var_18h]    ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:20
|      :|   0x00001b7d      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|      :|   0x00001b80      01d0           add eax, edx
|      :|   0x00001b82      0fb600         movzx eax, byte [eax]
|      :|   0x00001b85      0fbec0         movsx eax, al
|      :|   0x00001b88      8945f4         mov dword [var_ch], eax
|      :|   0x00001b8b      8b55e8         mov edx, dword [var_18h]    ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:21
|      :|   0x00001b8e      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|      :|   0x00001b91      01c2           add edx, eax
|      :|   0x00001b93      8b4dec         mov ecx, dword [var_14h]
|      :|   0x00001b96      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|      :|   0x00001b99      01c8           add eax, ecx
|      :|   0x00001b9b      0fb600         movzx eax, byte [eax]
|      :|   0x00001b9e      8802           mov byte [edx], al
|      :|   0x00001ba0      8b55ec         mov edx, dword [var_14h]    ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:22
|      :|   0x00001ba3      8b4508         mov eax, dword [arg_8h]     ; [0x8:4]=0
|      :|   0x00001ba6      01d0           add eax, edx
|      :|   0x00001ba8      8b55f4         mov edx, dword [var_ch]
|      :|   0x00001bab      8810           mov byte [eax], dl
|      :|   0x00001bad      8345e801       add dword [var_18h], 1      ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:18
|      :|   0x00001bb1      836dec01       sub dword [var_14h], 1
|      :|   ; CODE XREF from sym.r (0x1b78)
|      :`-> 0x00001bb5      8b45e8         mov eax, dword [var_18h]
|      :    0x00001bb8      3b45ec         cmp eax, dword [var_14h]
|      `==< 0x00001bbb      7cbd           jl 0x1b7a
|           0x00001bbd      8d642424       lea esp, [arg_24h]          ; /Users/kjsolo/StudioProjects/CoolLibrary/app/src/main/jni/a.c:24 ; 0x24 ; '$'
|           0x00001bc1      5b             pop ebx
|           0x00001bc2      5d             pop ebp
\           0x00001bc3      c3             ret
 */
// String reversing
void r(char *s) {
    int length = strlen(s); // shold be size_t

    int c, i = 0, j; // should be char, but anyway, I'm just reversing

    j = length - 1;

    while (i < j) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;

        i++;
        j--;
    }

    // Bad logic written by duangsuse
    /**
    for (int i = 0; i < length; i++) {
        for (int j = length - 1; j > 0; j--) {
            c = s[i];
            s[i] = s[j];
            s[j] = c;
        }
    }
    */
}

