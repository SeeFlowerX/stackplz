mkdir -p external && cd external

proxychains -q git clone https://android.googlesource.com/platform/bionic --depth=1

mkdir system && cd system

proxychains -q git clone https://android.googlesource.com/platform/system/core --depth=1

cd ..

proxychains -q git clone https://android.googlesource.com/platform/external/libbpf --depth=1

cd ..