export NDK_ROOT=/home/kali/Desktop/android-ndk-r25b

export PATH=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

make clean && BUILD_TAGS=forarm make

adb push bin/stackplz_arm /data/local/tmp