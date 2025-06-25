# noon

## 介绍

noon是一个高性能的网络入侵检测系统（IDS）传感器，支持多种协议和服务的模拟，旨在为网络安全提供高效、灵活的数据采集与分析能力。

## 功能
- 支持基本的网络接口监听、数据包捕获
- 支持自定义 BPF 过滤规则（如：`tcp port 80`）
- 支持将捕获的数据包保存为 JSON 或 PCAP 格式文件
- 支持订阅和集成威胁情报（todo）
- 支持多种协议识别（todo: dpi）
- 支持入侵检测规则（todo）
## 安装

```bash
go mod tidy
go build -trimpath -ldflags "-w -s"
```

## 启动程序

```bash
./noon
```
