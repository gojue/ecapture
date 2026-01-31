# eCapture 事件转发 API

本文档简要说明：**作为客户端，如何接收 eCapture 导出的事件和运行日志**，以及应该去看哪些已有文档和 Demo。

> 说明：
> 
> - 默认监听地址：`ws://127.0.0.1:28257`
> - 可通过命令行参数 `--ecaptureq` 修改监听地址，例如：`--ecaptureq=ws://127.0.0.1:28257/`
> - 所有接口均为 **Protobuf**

eCapture 目前有三种与“日志 / 事件输出”相关的参数：

- `--logaddr`：eCapture 自身运行日志输出位置（文本）
- `--eventaddr`：捕获到的事件日志输出位置（文本）
- `--ecaptureq`：通过 WebSocket + Protobuf(LogEntry) 实时转发运行日志和事件（结构化）

项目中已经包含了详细协议说明和一个完整 Demo，本文件只做“索引 + 行为说明”，方便你快速上手。

---

## 1. 三个输出参数的角色与优先级

### 1.1 `--logaddr`：运行日志（文本）

- 作用：指定 **eCapture 进程自身运行日志** 的输出位置。
- 支持形式：
    - 文件路径（如 `/var/log/ecapture.log`）
    - `tcp://host:port`
    - `ws://host:port/path` 或 `wss://host:port/path`
- 内容：初始化信息、模块启动、配置详情、错误日志等，格式为 **纯文本**。

### 1.2 `--eventaddr`：捕获事件日志（文本）

- 作用：指定 **捕获到的事件日志** 的输出位置。
- 支持形式与 `--logaddr` 类似（文件 / TCP / WebSocket），输出的是 **文本格式** 的事件日志。
- 适用场景：
    - 想直接将事件落到文件、TCP、现有日志系统中；
    - 下游对“文本日志”更友好，而暂时不需要 protobuf 解析。

### 1.3 `--ecaptureq`：统一事件转发（WebSocket + Protobuf）

- 作用：启动一个 **WebSocket 服务**（eCaptureQ），把 **运行日志 + 捕获事件** 统一以 `LogEntry` Protobuf 格式推送给 WebSocket 客户端。
- 参数示例：

  ```bash
  # 在本机 28257 端口启动 eCaptureQ
  sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/
  ```

- 输出特点：
    - 通过 WebSocket 推送；
    - 每条消息都是 `LogEntry` 的 protobuf 二进制编码；
    - `log_type` 字段区分：心跳 / 运行日志 / 事件。

### 1.4 `eventaddr` 与 `ecaptureq` 的关系

- `--eventaddr` 与 `--ecaptureq` 都是“事件输出通道”：
    - `--eventaddr`：**文本格式** 输出事件日志；
    - `--ecaptureq`：**Protobuf(LogEntry)** 格式输出事件和运行日志。
- **优先级**：
    - 当 **同时设置了 `--ecaptureq` 和 `--eventaddr`** 时，eCapture 会 **优先使用 `--ecaptureq`**；
    - 可以简单理解为：
        - 想要结构化的、可编程消费的事件流 → 用 `--ecaptureq`；
        - 只想把事件当作文本日志写出去 → 用 `--eventaddr`。

---

## 2. 使用 eCaptureQ WebSocket 接收事件（推荐）

如果你希望通过 WebSocket + Protobuf 的方式实时消费事件，推荐使用 `--ecaptureq`，并参考仓库中现有的文档和 Demo。

### 2.1 协议与消息结构文档

请阅读：

- Protobuf 协议定义：  
  `protobuf/proto/v1/ecaptureq.proto`
- 协议说明文档：  
  `protobuf/PROTOCOLS.md`

这两个文件一起定义了：

- 顶层消息 `LogEntry`：
    - `log_type`: `LOG_TYPE_HEARTBEAT` / `LOG_TYPE_PROCESS_LOG` / `LOG_TYPE_EVENT`
    - `payload`：根据 `log_type` 携带 `Heartbeat` / `Event` / `run_log`
- `Event` 字段：
    - `timestamp`, `uuid`, `src_ip`, `dst_ip`, `pid`, `pname`, `type`, `length`, `payload` 等
- `Heartbeat` 字段：
    - `timestamp`, `count`, `message`

这部分在 `PROTOCOLS.md` 里已经写得比较详细，可以直接对照实现。

### 2.2 官方 Go Demo 客户端

如果你用 Go，最简单的方式是直接参考官方 Demo：

- 目录：`examples/ecaptureq_client/`
    - 代码：`examples/ecaptureq_client/main.go`
    - 文档：`examples/ecaptureq_client/README.md`

该 Demo 已经帮你做好了：

1. 用 WebSocket 连接到 `--ecaptureq` 指定的地址；
2. 不断读取二进制消息；
3. 使用 `protobuf/gen/v1` 中的 `pb.LogEntry` 解码消息；
4. 按 `LogType` 分别处理：
    - 打印运行日志；
    - 展示捕获事件的详细信息（包括 payload 文本/hex/base64）；
    - 在 verbose 模式下显示心跳。

#### Demo 快速使用

```bash
# 1. 启动 eCapture，开启 eCaptureQ WebSocket
sudo ./ecapture tls --ecaptureq=ws://127.0.0.1:28257/

# 2. 构建客户端
cd examples/ecaptureq_client
go build -o ecaptureq_client main.go

# 3. 连接并查看事件
./ecaptureq_client -server ws://127.0.0.1:28257/
# 或
./ecaptureq_client -server ws://192.168.1.100:28257/ -verbose
```

如果你要集成到自己的系统，建议：

- 直接复制 `main.go` 里的接收 + 解码 + 分发逻辑；
- 替换“打印到终端”的部分为你自己的存储、分析或转发逻辑。

### 2.3 非 Go 语言的集成思路

对于其他语言（Python / Java / Node.js / Rust 等），可以按以下步骤：

1. 使用对应语言的 protobuf 工具，从 `protobuf/proto/v1/ecaptureq.proto` 生成代码；
2. 使用该语言的 WebSocket 客户端库，连接到 `ws://HOST:PORT/`（尾部包含 `/`）；
3. 在循环中读取二进制消息并反序列化为 `LogEntry`；
4. 根据 `log_type` 分别处理：心跳、运行日志、事件。

可以先跑一遍 `examples/ecaptureq_client` 看行为，再在你的语言里模仿同样的逻辑。

---

## 3. 使用 `eventaddr` / `logaddr` 接收纯文本日志

如果你不想处理 protobuf，只需要“文本日志”：

- 使用 `--logaddr` 输出 eCapture 自身运行日志；
- 使用 `--eventaddr` 输出捕获事件日志（文本）；

例如：

```bash
# 运行日志写到文件，事件日志写到另一个文件
./ecapture tls \
  --logaddr=/var/log/ecapture.log \
  --eventaddr=/var/log/ecapture-events.log
```

或：

```bash
# 事件日志通过 TCP 推送到远程
./ecapture tls \
  --eventaddr=tcp://192.168.1.100:9000
```

此时，你作为“客户端”只需要：

- 读取对应文件或 TCP 流；
- 按行（或约定的文本格式）解析日志内容即可。

**提醒**：如果你同时设置了 `--ecaptureq` 和 `--eventaddr`，事件会优先通过 `--ecaptureq` 的 WebSocket + protobuf 输出；`eventaddr` 更适合在没有使用 eCaptureQ 时提供文本日志。

---

## 4. 总结

- 想要 **结构化、可编程消费** 的事件流 → 使用 `--ecaptureq`，并参考：
    - `protobuf/proto/v1/ecaptureq.proto`
    - `protobuf/PROTOCOLS.md`
    - `examples/ecaptureq_client/`
- 想要 **文本日志**，方便直接写文件/管道 → 使用：
    - `--logaddr` 输出运行日志；
    - `--eventaddr` 输出事件日志（不使用 protobuf）；
- 同时设置时，`--ecaptureq` 优先级最高，优先通过 WebSocket + protobuf 方式转发。

本文件保持简洁，细节以仓库中已有的协议文档和 Demo 为准。