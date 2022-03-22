<hr>

## v0.1.4 (2022-03-22)

- 调整运行环境检测方式
  - 判断BTF支持的方法，改为优先判断`/sys/kernel/btf/vmlinu`文件，以及其他BTF特征的`vmlinux-*`目录等 。
  - 增加运行原理图。

### tls(openssl) 模块
- 支持gnutls 、 nspr 两个类库的数据捕获
- 重命名子命令，由`openssl`改为`tls`

<hr>

## v0.1.3 (2022-03-20)

- 增加运行环境检测
  - 检测linux kernel必须大于4.18 。
  - 检测kernel config中CONFIG_DEBUG_INFO_BTF必须有，且值为y。
- 去除编译生成的文件（./bin/、./assets/、./user/bytecode/）
- 整理go mod依赖文件

<hr>

## v0.1.1 (2022-03-19)

- 模块拆分，启用子命令模式
- 增加全局可选PID参数，针对特定PID进行数据捕获
- 增加hexdump打印模式

### openssl模块
- 支持自定义openssl的so路径。
- 支持hex进制的数据输出


### bash模块
- 支持自定义bash路径参数
- 支持自定义readline.so路径参数
- 支持hex进制的数据输出



<hr>

## v0.1.0 (2022-03-17)

### openssl模块
- 增加openssl的libssl.so的SSL/TLS数据抓包功能。
- 根据wget路径，自动选择libssl.so路径。


### bash模块
- 自动根据ENV查找bash
- 根据bash自动查找`readline.so`，并进行bash命令捕获