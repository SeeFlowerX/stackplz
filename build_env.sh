mkdir -p external && cd external

git clone https://android.googlesource.com/platform/external/libbpf --depth=1

cd ..

mkdir -p user/assets && cd user/assets

wget https://github.com/libbpf/bpftool/releases/download/v7.2.0-snapshot.0/bpftool-v7.2.0-snapshot.0-amd64.tar.gz

tar -zxvf bpftool-v7.2.0-snapshot.0-amd64.tar.gz

rm bpftool-v7.2.0-snapshot.0-amd64.tar.gz

chmod +x bpftool

wget https://github.com/SeeFlowerX/BTFHubForAndroid/raw/master/common-android12-5.10/a12-5.10-arm64.btf.tar.xz

tar -xvf a12-5.10-arm64.btf.tar.xz -C .
rm a12-5.10-arm64.btf.tar.xz

wget https://github.com/SeeFlowerX/BTFHubForAndroid/raw/master/rock5b/rock5b-5.10-f9d1b1529-arm64.btf.tar.xz

tar -xvf rock5b-5.10-f9d1b1529-arm64.btf.tar.xz -C .
rm rock5b-5.10-f9d1b1529-arm64.btf.tar.xz