# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.




add_library( # Sets the name of the library.
             nizk

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
                src/main/jni/com_nizkjnidemo_NizkJniKit.cpp
                src/main/jni/nizk.cpp
                src/main/jni/big.cpp
                src/main/jni/bn_pair.cpp
                src/main/jni/ecn.cpp
                src/main/jni/ecn2.cpp
                src/main/jni/zzn.cpp
                src/main/jni/zzn2.cpp
                src/main/jni/zzn4.cpp
                src/main/jni/zzn12a.cpp
                src/main/jni/mraes.c
                src/main/jni/mralloc.c
                src/main/jni/mrarth0.c
                src/main/jni/mrarth1.c
                src/main/jni/mrarth2.c
                src/main/jni/mrarth3.c
                src/main/jni/mrbits.c
                src/main/jni/mrbrick.c
                src/main/jni/mrcore.c
                src/main/jni/mrcrt.c
                src/main/jni/mrcurve.c
                src/main/jni/mrebrick.c
                src/main/jni/mrec2m.c
                src/main/jni/mrecn2.c
                src/main/jni/mrfast.c
                src/main/jni/mrgcd.c
                src/main/jni/mrgcm.c
                src/main/jni/mrgf2m.c
                src/main/jni/mrio1.c
                src/main/jni/mrio2.c
                src/main/jni/mrjack.c
                src/main/jni/mrlucas.c
                src/main/jni/mrmonty.c
                src/main/jni/mrpower.c
                src/main/jni/mrprime.c
                src/main/jni/mrrand.c
                src/main/jni/mrscrt.c
                src/main/jni/mrshs.c
                src/main/jni/mrshs256.c
                src/main/jni/mrshs512.c
                src/main/jni/mrsmall.c
                src/main/jni/mrsroot.c
                src/main/jni/mrstrong.c
                src/main/jni/mrxgcd.c
                src/main/jni/mrzzn2.c
                src/main/jni/mrzzn2b.c
                src/main/jni/mrzzn3.c
                src/main/jni/mrzzn4.c
             )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       nizk

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}
                        )
