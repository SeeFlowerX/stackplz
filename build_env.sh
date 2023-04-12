mkdir -p external && cd external

wget https://github.com/libbpf/bpftool/releases/download/v7.2.0-snapshot.0/bpftool-v7.2.0-snapshot.0-amd64.tar.gz

tar -zxvf bpftool-v7.2.0-snapshot.0-amd64.tar.gz

rm bpftool-v7.2.0-snapshot.0-amd64.tar.gz

chmod +x bpftool

git clone https://android.googlesource.com/platform/external/libbpf --depth=1

cd ..