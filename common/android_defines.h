#ifndef __android_defines_h__
#define __android_defines_h__

#ifndef ANDROID
#error including android defines on non android build
#endif
/* not defined in android, though is available from linux kernel 2.6.30 onwards */

#define EFD_SEMAPHORE (0x00000001)


#endif /*__android_defines_h__*/
