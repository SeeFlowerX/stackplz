# stackplz

stackplz是一款基于eBPF的堆栈追踪工具，本项目主要参考以下项目和文章，致谢

- [eCapture(旁观者)](https://github.com/ehids/ecapture)
- [定制bcc/ebpf在android平台上实现基于dwarf的用户态栈回溯](https://bbs.pediy.com/thread-274546.htm)

特性：

- 对原进程影响极小
- 详细的堆栈信息

# 要求

- 手机有root权限
- 内核大于等于4.14，可使用`uname -r`查看自己手机的内核信息
- Android 11以及之后的系统版本
- 仅支持对64位库进行hook

![](./images/Snipaste_2022-11-09_14-26-47.png)

# 使用

从release下载预编译好的二进制文件即可，或者自行编译，产物在`bin`目录下

1. 推送到手机的`/data/local/tmp`目录下，添加可执行权限即可

```bash
adb push stackplz /data/local/tmp
adb shell
su
chmod +x /data/local/tmp/stackplz
```

2. 第一次使用时需要释放库文件，请使用下面的命令

```bash
/data/local/tmp/stackplz stack --prepare
```

![](./images/Snipaste_2022-11-09_14-25-46.png)

3. 参考下列命令示例进行hook

**必须指定目标进程的uid**，通过包名获取uid的命令如下

```bash
dumpsys package com.sfx.ebpf | grep userId=
```

**简单使用**：`--libpath`默认为`/apex/com.android.runtime/lib64/bionic/libc.so`，所以下面的命令是针对uid为10245的进程，hook对应libc.so的`open`函数，这里是通过uid过滤的，即使是多进程也不影响

```bash
./stackplz stack --uid 10224 --symbol open --unwindstack
```

![](./images/Snipaste_2022-11-09_15-32-03.png)

还可以显示hook时的完整寄存器信息

```bash
./stackplz stack --uid 10224 --symbol open --unwindstack --show-regs
```

![](./images/Snipaste_2022-11-09_16-47-16.png)


**复杂使用**：指定偏移，对任意的APP三方库进行hook追踪，记得uid要对应

```bash
./stackplz stack --uid 10224 --libpath /data/app/~~d6FTHd4woitjnG95rjCv1w==/com.sfx.ebpf-YyPF9u5v8CBZD6OOfV4XQg==/lib/arm64/libnative-lib.so --offset 0xF37C --unwindstack
```

eBPF hook需要提供完整的库文件路径，所以我们需要先查看要hook的库具体是啥路径

最准确的做法是当程序运行时，查看程序的`/proc/{pid}/maps`内容，这里的路径是啥就是啥

![](./images/Snipaste_2022-11-09_15-23-31.png)

路径看起来有些随机字符，但是APP安装后这个是不会变的，所以获取一次就行

效果如图：

![](./images/Snipaste_2022-11-09_15-28-12.png)

查看跟单帮助信息使用如下命令：

- `/data/local/tmp/stackplz -h`
- `/data/local/tmp/stackplz stack -h`

输出到日志文件添加`--log-file tmp.log`

只输出到日志，不输出到终端再加一个`--quiet`即可

# 编译

在linux x86_64环境下编译

首先准备必要的外部代码，记得挂全局代理或者使用`proxychains`等工具

```bash
./build_env.sh
```

然后下载ndk并解压，我这里选的是`android-ndk-r25b`

然后修改`build.sh`中的`NDK_ROOT`路径，执行下面的命令即可完成编译，产物在`bin`目录下

```bash
./build.sh
```

将可执行文件推送到手机上后就可以开始使用了

```bash
adb push bin/stackplz /data/local/tmp
```

# TODO

- 通过配置文件实现批量hook
- 优化代码逻辑...

# Q & A

1. 使用时手机卡住并重启怎么办？

经过分析，出现这种情况是因为`bpf_perf_event_output`参数三使用的是`BPF_F_CURRENT_CPU`导致

借助[vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf)把boot.img转换成ELF文件，通过对比分析

发现出现崩溃的内核走到了`brk 1`指令，但是这个分支本不该存在，详细分析过程后续会单独出一篇文章

![](./images/FkCOXtSfHjSxSxOu25dkx5rqPp9B.png)

对于此种情况，建议升级系统到Android 12版本一般可以避免

~~(或者尝试自己编译下内核？)~~

2. `preload_libs`里面的库怎么编译的？

参见：[unwinddaemon](https://github.com/SeeFlowerX/unwinddaemon)

# 交流

安卓逆向、eBPF技术、反调对抗、搞机...欢迎加入讨论

![](./images/Snipaste_2022-11-09_17-26-46.png)

后续将就本项目从0到1的过程分享系列文章，欢迎关注