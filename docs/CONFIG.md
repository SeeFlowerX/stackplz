# 配置文件文档

## 命令

tests目录下有一些示例配置，供参考

```bash
adb push tests /data/local/tmp
./stackplz -n com.coolapk.market -c tests/config_uprobe_test_complex.json --dumphex --color
```

## 字段说明

**1. 基础字段**

- **type** 表示hook点类型
- **library** 【uprobe专用】，即要下uprobe hook的ELF文件
    - 通常情况下只需要提供文件名，如果出现找不到的情况，请指定完整路径
    - 对于split apk中的so同样提供了支持
- **points** 表示hook点列表
    - 注意，对于uprobe，单次hook最多只支持6个，如果还有更多hook点，需要另外开shell执行stackplz

**2. points元素字段**

- **nr** 【syscall专用】，即系统调用号，必须唯一
- **name** 即hook点的名字
    - 对于uprobe，这个字段有两种写法
        - 目标库的符号，可以通过下面的命令确定有没有符号
            - `readelf -s /path/to/elf | grep strstr`
        - 目标库的偏移
            - 使用`0x`开头的十六进制字符串
    - 对于syscall，这个字段是系统调用号的名称，可以随便自定义
- **params** 即命中hook点时，要读取的参数的配置
    - 默认情况下，按照寄存器顺序进行参数读取

**3. params元素字段**

- **name** 即参数名，可以省略，省略时会按照`a + {元素索引}`的方式命名
    - 【特别情况】，对于syscall，最后一个参数的名称必须是`ret`，通常将其类型指定为`ptr`或者`int`
- **type** 即参数类型，完整的可选参数类型请看下一小节的说明
    - 注意，如果需要将类型指示为指针，那么在类型名前加`*`即可
- **reg** 即参数读取时的寄存器，可以省略，省略时元素索引作为寄存器索引
- **read_op** 要读取的参数不是寄存器的时候使用，比如读取栈上的数据，语法如下：
    - `x0+152.` 读取`x0+152`的值作为指针，然后再读取`type`类型的数据
    - 规则1，必须以寄存器名开始
    - 规则2，可以存在`+/-`运算
    - 规则3，`.`表示取一次指针
    - 规则4，可以多次嵌套
    - 规则5，设置该字段时，`reg`字段不生效
- **format** 即解析结果时的格式化配置
    - 绝大部分情况下，会根据`type`字段自动处理，但还是有些情况需要进一步转换以获得更好的可读性
    - `hex fcntl_flags statx_flags unlink_flags socket_flags perm_flags msg_flags`
- **more** 【syscall专用】，表示在何时读取结构体详细信息，可选项：
    - `enter`，表示只会在`sys_enter`的时候读取结构体详细内容
    - `exit`，表示只会在`sys_enter`的时候读取结构体详细内容
    - `all`，表示在`sys_enter/sys_exit`的时候都会读取结构体详细内容
- **size** 这是针对`buf/buffer`、`iovec`等类型的扩展字段，即表示要读取的元素大小，或者指示元素大小的寄存器
- **filter** 过滤配置，是一个字符串列表，一个参数可以配置多个过滤条件，格式为`{类型}:{值}`
    - `w/white` 字符串白名单
    - `b/black` 字符串黑名单
    - `eq/equal` 参数的值等于配置的值
    - `lt/less` 参数的值小于配置的值
    - `gt/greater` 参数的值大于配置的值

**4. 过滤逻辑**

1. 读取结果与任意字符串黑名单规则之一匹配，跳过
2. 读取结果与任意字符串不与任何白名单规则匹配，跳过
3. 读取结果不满足`eq/lt/gt`条件时，跳过

uprobe和syscall的配置文件略有差异，具体请看下面的例子

**5. type的可选项**

一些基础类型：

- ptr
- int/uint/int8/uint8/int16/uint16/int32/uint32/int64/uint64
    - **tips!** int/uint 与 int32/uint32 等效
- str 即C字符串，`\x00`视为字符串结尾
- std 即std::string
- string_array 该类型用于execve的参数解析
- int_arr uint_arr ptr_arr 即对应类型的数组，注意同时通过`size`指定大小
- size_t 与uint64等效
- ssize_t 与int64等效
- socklen_t 与uint32等效

一些内置的复杂类型：

- stack_t
- timespec
- sigset
- siginfo
- sigaction
- epollevent
- pollfd
- dirent
- ittmerspec
- rusage
- utsname
- timeval
- timezone
- sysinfo
- stat
- statfs
- iovec
- msghdr
- sockaddr

## uprobe

解释：

1. 对`libc.so`的`__openat`下hook，读取`x1`为`str`类型，只记录以`/data/data`开头的字符串
2. 对`libc.so`的`strstr`下hook，读取`x0`和`x1`为`str`类型，参数名分别为`haystack`和`needle`

```json
{
    "type": "uprobe",
    "library": "libc.so",
    "points": [
        {
            "name": "__openat",
            "params": [
                {"type": "str", "reg": "x1", "filter": ["w:/data/data"]}
            ]
        },
        {
            "name": "strstr",
            "params": [
                {"name": "haystack", "type": "str"},
                {"name": "needle", "type": "str"}
            ]
        }
    ]
}
```

更复杂的例子，在`call_constructors`这里解析`soinfo`的内容

- 参数1，输出的是`call_constructors`的参数，也就是`soinfo`指针
- 参数2，输出的是`soinfo->soname`，即so名，并且过滤了`libjiagu`
- 参数3，输出的是`soinfo->init_array_count_`，即init_array数量，注意这是一个指针
- 参数4，输出的是`soinfo->init_array_`，即init_array，大小固定6个

```json
{
    "type": "uprobe",
    "library": "linker64",
    "points": [
        {
            "name": "__dl__ZN6soinfo17call_constructorsEv",
            "params": [
                {"type": "ptr"},
                {"type": "std", "read_op": "x0+408", "filter": ["w:libjiagu"]},
                {"type": "*int", "read_op": "x0+160"},
                {"type": "ptr_arr", "size":"6", "read_op": "x0+152."}
            ]
        }
    ]
}
```

日志输出效果：

```log
[14672|14672|.coolapk.market] __dl__ZN6soinfo17call_constructorsEv(a0=0x7d60160560, a1=0x7d601606f8(libjiagu.so), a2=0x7d60160600(4), a3=0x7a2dc98cc0[0x7a2dc3bca4, 0x7a2dc352c0, 0x7a2dc35330, 0x0, 0x7a2dc352b4, 0x0]) LR:0x7d613292a8 PC:0x7d6132ff1c SP:0x7ff1422f60
[14732|14732|:xg_vip_service] __dl__ZN6soinfo17call_constructorsEv(a0=0x7d60160560, a1=0x7d601606f8(libjiagu.so), a2=0x7d60160600(4), a3=0x7a2b723cc0[0x7a2b6c6ca4, 0x7a2b6c02c0, 0x7a2b6c0330, 0x0, 0x7a2b6c02b4, 0x0]) LR:0x7d613292a8 PC:0x7d6132ff1c SP:0x7ff1422f60
```

## syscall

当使用配置文件时，如果不通过`-s/--syscall`具体指定要下hook的syscall，那么配置文件中的所有syscall都会被hook

解释：

1. 对系统调用号为`29`的`ioctl`下hook，依次读取寄存器，类型依次是`int ptr ptr ptr`；其中`cmd`参数必须为`0xc0306201`
2. 对系统调用号为`206`的`sendto`下hook，这里的第二个参数类型为`buf`，必须指定`size`，对于该系统调用，第二个参数的大小由第三个参数指示，即`x2`；如果将`size`指定为具体大小，那么将读取固定大小的值

```json
{
    "type": "syscall",
    "points": [
        {
            "nr": 29,
            "name": "ioctl",
            "params": [
                {"name": "fd", "type": "int"},
                {"name": "cmd", "type": "ptr", "filter": ["eq:0xc0306201"]},
                {"name": "arg", "type": "ptr"},
                {"name": "ret", "type": "ptr"}
            ]
        },
        {
            "nr": 206,
            "name": "sendto",
            "params": [
                {"name": "sockfd", "type": "int"},
                {"name": "buf", "type": "buf", "more":"enter", "size": "x2"},
                {"name": "len", "type": "size_t"},
                {"name": "flags", "type": "int", "format": "msg_flags"},
                {"name": "addr", "type": "sockaddr"},
                {"name": "addrlen", "type": "socklen_t"},
                {"name": "ret", "type": "int"}
            ]
        }
    ]
}
```

## 其他

**1. 过滤向特定ip发起的connect调用**

```bash
./stackplz -n package_name -c tests/config_syscall_connect_filter.json -s connect --color --stack -o tmp.log
```

对于这种情况，将其转换为对addr参数，即sockaddr类型，特定偏移处读取ip的数据，比较二进制数据

由于存在family为ipv6但是实际ip为ipv4的情况，因此准备两个过滤条件

```json
{
    "type": "syscall",
    "points": [
        {
            "nr": 203, 
            "name": "connect",
            "params":[
                {"name": "sockfd", "type": "int"},
                {"name": "addr", "type": "sockaddr"},
                {"name": "addrlen", "type": "uint32"},
                {"name": "v4_fliter", "type": "buf", "size":"4", "reg": "x1", "read_op": "x1+0x4", "filter": ["addr:1.2.3.4"]},
                {"name": "v6_fliter", "type": "buf", "size":"4", "reg": "x1", "read_op": "x1+0x14", "filter": ["addr:1.1.1.1"]},
                {"name": "ret", "type": "int"}
            ]
        }
    ]
}
```

**2. 过滤AF_INET和AF_INET6的connect调用**

```bash
./stackplz -n package_name -c tests/config_syscall_connect_filter2.json -s connect -o tmp.log
```

```json
{
    "type": "syscall",
    "points": [
        {
            "nr": 203, 
            "name": "connect",
            "params":[
                {"name": "sockfd", "type": "int"},
                {"name": "addr", "type": "sockaddr"},
                {"name": "addrlen", "type": "uint32"},
                {"name": "net_fliter", "type": "buf", "size":"1", "reg": "x1", "filter": ["bx:02", "bx:0a"]},
                {"name": "ret", "type": "int"}
            ]
        }
    ]
}
```