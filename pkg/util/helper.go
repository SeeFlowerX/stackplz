package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func IntToBytes(n int) []byte {
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, x)
	return bytesBuffer.Bytes()
}

func RemoveDuplication_map(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}

func FindLib(library string, search_paths []string) (string, error) {
	// 尝试在给定的路径中搜索 主要目的是方便用户输入库名即可
	search_paths = RemoveDuplication_map(search_paths)
	// 以 / 开头的认为是完整路径 否则在提供的路径中查找
	if strings.HasPrefix(library, "/") {
		_, err := os.Stat(library)
		if err != nil {
			// 出现异常 提示对应的错误信息
			if os.IsNotExist(err) {
				return library, fmt.Errorf("%s not exists", library)
			}
			return library, err
		}
	} else {
		var full_paths []string
		for _, search_path := range search_paths {
			// 去掉末尾可能存在的 /
			check_path := strings.TrimRight(search_path, "/") + "/" + library
			_, err := os.Stat(check_path)
			if err != nil {
				// 这里在debug模式下打印出来
				continue
			}
			full_paths = append(full_paths, check_path)
		}
		if len(full_paths) == 0 {
			// 没找到
			return library, fmt.Errorf("can not find %s in these paths\n%s", library, strings.Join(search_paths[:], "\n\t"))
		}
		if len(full_paths) > 1 {
			// 在已有的搜索路径下可能存在多个同名的库 提示用户指定全路径
			return library, fmt.Errorf("find %d libs with the same name\n%s", len(full_paths), strings.Join(full_paths[:], "\n\t"))
		}
		// 修正为完整路径
		library = full_paths[0]
	}
	return library, nil
}
