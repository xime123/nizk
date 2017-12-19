LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

APP_PLATFORM := android-19

APP_STL      := gnustl_shared

LOCAL_MODULE    := nizk
LOCAL_LDLIBS += -llog
LOCAL_ALLOW_UNDEFINED_SYMBOLS := true











LOCAL_SRC_FILES :=   com_nizkjnidemo_NizkJniKit.cpp
LOCAL_SRC_FILES +=                    nizk.cpp
LOCAL_SRC_FILES +=                    big.cpp
LOCAL_SRC_FILES +=                    bn_pair.cpp
LOCAL_SRC_FILES +=                    ecn.cpp
LOCAL_SRC_FILES +=                    ecn2.cpp
LOCAL_SRC_FILES +=                    zzn.cpp
LOCAL_SRC_FILES +=                    zzn2.cpp
LOCAL_SRC_FILES +=                    zzn4.cpp
LOCAL_SRC_FILES +=                    zzn12a.cpp
LOCAL_SRC_FILES +=                    Test.cpp
LOCAL_SRC_FILES +=                    mraes.c
LOCAL_SRC_FILES +=                    mralloc.c
LOCAL_SRC_FILES +=                        mrarth0.c
LOCAL_SRC_FILES +=                         mrarth1.c
LOCAL_SRC_FILES +=                         mrarth2.c
LOCAL_SRC_FILES +=                          mrarth3.c
LOCAL_SRC_FILES +=                          mrbits.c
LOCAL_SRC_FILES +=                          mrbrick.c
LOCAL_SRC_FILES +=                         mrcore.c
LOCAL_SRC_FILES +=                          mrcrt.c
LOCAL_SRC_FILES +=                          mrcurve.c
LOCAL_SRC_FILES +=                          mrebrick.c
LOCAL_SRC_FILES +=                          mrec2m.c
LOCAL_SRC_FILES +=                          mrecn2.c
LOCAL_SRC_FILES +=                          mrfast.c
LOCAL_SRC_FILES +=                          mrgcd.c
LOCAL_SRC_FILES +=                          mrgcm.c
LOCAL_SRC_FILES +=                          mrgf2m.c
LOCAL_SRC_FILES +=                          mrio1.c
LOCAL_SRC_FILES +=                          mrio2.c
LOCAL_SRC_FILES +=                          mrjack.c
LOCAL_SRC_FILES +=                          mrlucas.c
LOCAL_SRC_FILES +=                          mrmonty.c
LOCAL_SRC_FILES +=                          mrpower.c
LOCAL_SRC_FILES +=                          mrprime.c
LOCAL_SRC_FILES +=                          mrrand.c
LOCAL_SRC_FILES +=                          mrscrt.c
LOCAL_SRC_FILES +=                          mrshs.c
LOCAL_SRC_FILES +=                          mrshs256.c
LOCAL_SRC_FILES +=                          mrshs512.c
LOCAL_SRC_FILES +=                          mrsmall.c
LOCAL_SRC_FILES +=                          mrsroot.c
LOCAL_SRC_FILES +=                          mrstrong.c
LOCAL_SRC_FILES +=                          mrxgcd.c
LOCAL_SRC_FILES +=                          mrzzn2.c
LOCAL_SRC_FILES +=                          mrzzn2b.c
LOCAL_SRC_FILES +=                          mrzzn3.c
LOCAL_SRC_FILES +=                          mrzzn4.c



include $(BUILD_SHARED_LIBRARY)   #如果编译静态库，需要Application.mk
