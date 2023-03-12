export NDK_ROOT=/home/kali/Desktop/android-ndk-r25b

export PATH=$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

make clean && make

adb push bin/stackplz /data/local/tmp
adb push config.json /data/local/tmp