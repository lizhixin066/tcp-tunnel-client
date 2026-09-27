# TCP 内网穿透客户端（Windows）

这是一个原生 C++ / Win32 图形客户端。窗口、状态、日志和错误提示均使用简体中文。客户端从内网主动连接 [Ubuntu 服务端](https://github.com/lizhixin066/tcp-tunnel-server)，把服务端公开端口收到的 TCP 连接转发至本机或内网里的 TCP 服务。客户端无需配置路由器入站端口映射。

## 仓库内容

```text
.
├── Tunnel.sln                     Visual Studio 解决方案
├── client/
│   ├── TunnelClient.vcxproj        原生 Visual Studio C++ 项目
│   ├── TunnelClient.vcxproj.filters
│   └── main.cpp                    Win32 窗口程序，关键流程有中文注释
├── docs/protocol.md               客户端与服务端通信协议
└── .github/workflows/build.yml    VS 2022 自动编译和发布
```

## 用 Visual Studio 编译

在 Windows 上安装 Visual Studio 2022 或 2026，勾选“使用 C++ 的桌面开发”。打开 [Tunnel.sln](Tunnel.sln)，选择 `Release | x64`，执行“生成解决方案”。可执行文件位于 `bin/x64/Release/TunnelClient.exe`。本项目使用原生 `.sln` 和 `.vcxproj`，不使用 CMake。

也可以在 Visual Studio 开发者命令提示符中运行：

```bat
msbuild Tunnel.sln /m /p:Configuration=Release /p:Platform=x64
```

推送到 GitHub 的 `main` 分支后，GitHub Actions 会用 Windows 2022 和 Visual Studio 2022 编译，并在 Actions 的构建产物和最新 Release 中提供 `TunnelClient.exe`。

## 连接服务端

先按 [服务端仓库](https://github.com/lizhixin066/tcp-tunnel-server) 的说明部署 Ubuntu 服务端，记下服务端生成的密钥和控制端口。假设本地 TCP 服务在 `127.0.0.1:3000`，Ubuntu 服务端 IP 为 `203.0.113.10`，公开端口为 `8080`：

| 窗口设置 | 示例 |
| --- | --- |
| 服务端地址 | `203.0.113.10` |
| 控制端口 | `7000` |
| 本地地址 | `127.0.0.1` |
| 本地端口 | `3000` |
| 密钥 | 服务端安装时显示的密钥 |

点击“连接”。之后访问 `203.0.113.10:8080`，请求会转发至客户端能访问的 `127.0.0.1:3000`。服务端 IP 和公开端口应替换为实际值。地址栏也支持主机名；主机名解析使用 Windows 系统 DNS。

当前一个服务端实例只提供一组 TCP 端口映射，且只允许一个客户端在线。暂不支持 UDP、域名转发或 HTTP 路由。协议格式参见 [通信协议](docs/protocol.md)。客户端与服务端需使用兼容的协议版本。

## 安全

目前密钥认证与转发流量没有加密。公网使用时，请在 WireGuard、VPN 或其他可信加密通道中传输，并限制服务端端口的访问范围。公开端口会暴露本地服务，该服务自身也应配置认证和访问控制。

项目按 [MIT 许可证](LICENSE) 开源。
