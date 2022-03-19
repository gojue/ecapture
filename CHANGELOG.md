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