mkdir -p external && cd external

git clone https://android.googlesource.com/platform/bionic --depth=1

mkdir system && cd system

git clone https://android.googlesource.com/platform/system/core --depth=1

cd ..

git clone https://android.googlesource.com/platform/external/libbpf --depth=1

cd ..