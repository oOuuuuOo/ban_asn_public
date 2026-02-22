# ban_asn

[English](README.md) | 简体中文

`ban_asn` 是一个基于 Linux `nftables` 的 ASN 与国家 CIDR 黑名单工具，支持规则持久化、增量更新与完整安装生命周期管理。

## 功能特性

- 基于 ASN 与国家的 CIDR 封禁
- 通过 `systemd` 支持开机持久化恢复
- 支持按 ASN/国家目标进行增量更新
- 安装后提供全局命令 `oban`
- 支持 `-cn` 中文输出模式

## 防护价值主线

`ban_asn` 的核心目标只有一条：让命中策略的来源更接近“超时/无响应”的感知，同时减少“活主机 + 服务类型”这类可利用证据。

| 视角 | 典型感知 |
| --- | --- |
| 无策略 | 暴露更多活主机与服务指纹信号，日志噪声与资源浪费更明显 |
| 使用 `ban_asn` | 命中网段更容易感知为超时/无响应，指纹证据减少，运维更可控 |

### 高收益场景

- 互联网扫段与端口探测
- 来自高风险网段的爆破与机器人探测
- 公网服务上的自动化侦察/爬虫噪声

### 实际优势

- 通过内核层 `drop` 提前削减低价值流量
- 提升安全与运维日志的有效信号占比
- 降低应用层重复噪声与基线资源压力
- 基于策略（`ASN` + 国家 CIDR）可重复执行并可持久恢复

### 边界说明

这是底层基线防护，不替代 WAF、IDS、鉴权与限流，而是与它们叠加使用。

## 快速开始

一键安装：

```bash
curl -sL ouo.run/ban | bash
```

中文输出模式：

```bash
curl -sL ouo.run/ban | bash -s -- -cn
```

强制重装：

```bash
curl -sL ouo.run/ban | bash -s -- --force-reinstall
```

## 命令示例

```bash
oban ban
oban status
oban config
oban config edit
oban config edit --check
oban update all
oban version
```

## 策略配置

配置文件路径：

```bash
/etc/ban_asn/ban_asn.conf
```

示例：

```bash
ASNS="45102 37963 132203"
COUNTRIES="ru kp ir"
```

修改后应用：

```bash
oban ban
```

## 默认封禁集合

默认 `ASNS`（`as-name` 来自 `whois.radb.net` 查询结果，可能随时间变化）：

| ASN | AS-Name (RADB) | Country (RADB) |
| --- | --- | --- |
| 45102 | CNNIC-ALIBABA-CN-NET-AP | US |
| 37963 | ALIBABA-CN-NET | CN |
| 132203 | TENCENT-NET-AP-CN | CN |
| 55990 | HWCSNET | CN |
| 136907 | HWCSNET | HK |
| 45050 | FR-HIPAY-AS | N/A |
| 135377 | UCLOUD-HK-AS-AP | HK |
| 55967 | Baidu | CN |
| 16509 | Amazon | N/A |
| 14618 | Amazon-AES-IAD | N/A |
| 15169 | Google | N/A |
| 8075 | Microsoft | N/A |
| 31898 | ORACLE-OCI-31898 | N/A |
| 14061 | DIGITALOCEAN | N/A |
| 63949 | AKAMAI-LINODE-AP | SG |
| 9009 | M247 | N/A |

默认 `COUNTRIES`（ISO 3166-1 alpha-2）：

| 代码 | 国家/地区 |
| --- | --- |
| kp | 朝鲜 |
| iq | 伊拉克 |
| af | 阿富汗 |
| ru | 俄罗斯 |
| cu | 古巴 |
| ir | 伊朗 |
| by | 白俄罗斯 |
| vn | 越南 |
| id | 印度尼西亚 |
| br | 巴西 |
| pk | 巴基斯坦 |
| ua | 乌克兰 |

脚本数据来源：

- ASN 网段（主来源）：`whois -h whois.radb.net -- "-i origin AS<asn>"`
- ASN 网段（回退 1）：`ip.guide/AS<asn>`
- ASN 网段（回退 2）：`api.hackertarget.com/aslookup/?q=AS<asn>`
- 国家网段：`www.ipdeny.com/ipblocks/data/countries/<cc>.zone`
- 网段归并：Python `ipaddress.collapse_addresses()`

该策略不是 GeoIP 表驱动，而是基于路由归属/BGP 风格数据与国家 CIDR zone 文件组合得到。

## 仓库范围

该公开仓库仅包含面向公开使用的核心脚本与文档。