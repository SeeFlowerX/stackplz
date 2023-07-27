package util

import (
    "bufio"
    "compress/gzip"
    "fmt"
    "os"
    "regexp"
    "strings"
)

const (
    BOOT_CONFIG_PATH       = "/proc/config.gz"
    CONFIG_DEBUG_INFO_BTF  = "CONFIG_DEBUG_INFO_BTF"
    SYS_KERNEL_BTF_VMLINUX = "/sys/kernel/btf/vmlinux"
)

var (
    // use same list of locations as libbpf
    // https://android.googlesource.com/platform/external/libbpf/

    locations = []string{
        "/sys/kernel/btf/vmlinux",
    }
)

func GetSystemConfig() (map[string]string, error) {
    return getAndroidConfig(BOOT_CONFIG_PATH)
}

func getAndroidConfig(filename string) (map[string]string, error) {
    var KernelConfig = make(map[string]string)
    // Open file bootConf.
    f, err := os.Open(filename)
    if err != nil {
        return KernelConfig, err
    }
    defer f.Close()

    // check if the file is gzipped
    var magic []byte
    var i int
    magic = make([]byte, 2)
    i, err = f.Read(magic)
    if err != nil {
        return KernelConfig, err
    }
    if i != 2 {
        return KernelConfig, fmt.Errorf("read %d bytes, expected 2", i)
    }

    var s *bufio.Scanner
    _, err = f.Seek(0, 0)
    if err != nil {
        return KernelConfig, err
    }

    var reader *gzip.Reader
    //magic number for gzip is 0x1f8b
    if magic[0] == 0x1f && magic[1] == 0x8b {
        // gzip file
        reader, err = gzip.NewReader(f)
        if err != nil {
            return KernelConfig, err
        }
        s = bufio.NewScanner(reader)
    } else {
        // not gzip file
        s = bufio.NewScanner(f)
    }

    if err = parse(s, KernelConfig); err != nil {
        return KernelConfig, err
    }
    return KernelConfig, nil
}

// IsContainedInCgroup returns true if the process is running in a container.
func IsContainer() (bool, error) {
    return false, nil
}

func parse(s *bufio.Scanner, p map[string]string) error {
    r, _ := regexp.Compile("^(?:# *)?(CONFIG_\\w*)(?:=| )(y|n|m|is not set|\\d+|0x.+|\".*\")$")

    for s.Scan() {

        t := s.Text()

        // Skip line if empty.
        if t == "" {
            continue
        }

        // 0 is the match of the entire expression,
        // 1 is the key, 2 is the value.
        m := r.FindStringSubmatch(t)
        if m == nil {
            continue
        }

        if len(m) != 3 {
            return fmt.Errorf("match is not 3 chars long: %v", m)
        }
        // Remove all leading and trailing double quotes from the value.
        if len(m[2]) > 1 {
            m[2] = strings.Trim(m[2], "\"")
        }

        // Insert entry into map.
        p[m[1]] = m[2]
    }

    if err := s.Err(); err != nil {
        return err
    }

    return nil
}
