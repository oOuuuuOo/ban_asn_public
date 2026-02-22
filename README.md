# ban_asn

English | [简体中文](README.zh-CN.md)

![Version](//img.shields.io/badge/version-v4.2.2-blue)
![Platform](//img.shields.io/badge/platform-linux-success)
![License](//img.shields.io/badge/license-MIT-green)

`ban_asn` is a Linux `nftables`-based blacklist tool for ASN and country CIDR blocking, with persistent rules, update workflows, and full install lifecycle management.

## Features

- ASN and country-based CIDR blocking
- Persistent restore on reboot via `systemd`
- Incremental updates by ASN/country target
- Global command `oban` after installation
- Optional Chinese output mode with `-cn`

## Defensive Value

`ban_asn` follows one core objective: make blocked sources perceive your host closer to timeout/silence, and reduce evidence that helps identify an active host and service stack.

| View | Typical Perception |
| --- | --- |
| No policy | More “live host + service type” clues, noisier logs, and higher background waste |
| With `ban_asn` | More timeout/silence outcomes for blocked ranges, less fingerprint evidence, cleaner operations |

### Where It Helps Most

- Internet-wide scanning and port probing
- Brute-force and bot probing from known abusive ranges
- Automated recon/crawler noise on public-facing services

### Practical Advantages

- Earlier low-value traffic reduction at kernel level (`drop` behavior)
- Better signal-to-noise ratio in security and operations logs
- Lower repetitive application-layer noise and baseline resource pressure
- Repeatable policy enforcement (`ASN` + country CIDRs) with persistent restore

### Boundary

This is a low-level baseline control. It complements (not replaces) WAF, IDS, authentication, and rate limiting.

## Quick Start

One-line install:

```bash
curl -sL ouo.run/ban | bash
```

Chinese output mode:

```bash
curl -sL ouo.run/ban | bash -s -- -cn
```

Force reinstall:

```bash
curl -sL ouo.run/ban | bash -s -- --force-reinstall
```

## CLI Usage

```bash
oban ban
oban status
oban config
oban config edit
oban config edit --check
oban update all
oban version
```

## Policy Configuration

Configuration file:

```bash
/etc/ban_asn/ban_asn.conf
```

Example:

```bash
ASNS="45102 37963 132203"
COUNTRIES="ru kp ir"
```

Apply changes:

```bash
oban ban
```

## Default Blocking Set

Default `ASNS` (observed `as-name` from `whois.radb.net`, values may change over time):

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

Default `COUNTRIES` (ISO 3166-1 alpha-2):

| Code | Country |
| --- | --- |
| kp | North Korea |
| iq | Iraq |
| af | Afghanistan |
| ru | Russia |
| cu | Cuba |
| ir | Iran |
| by | Belarus |
| vn | Vietnam |
| id | Indonesia |
| br | Brazil |
| pk | Pakistan |
| ua | Ukraine |

Data sources used by the script:

- ASN CIDRs (primary): `whois -h whois.radb.net -- "-i origin AS<asn>"`
- ASN CIDRs (fallback): `ip.guide/AS<asn>`
- ASN CIDRs (fallback 2): `api.hackertarget.com/aslookup/?q=AS<asn>`
- Country CIDRs: `www.ipdeny.com/ipblocks/data/countries/<cc>.zone`
- CIDR normalization: Python `ipaddress.collapse_addresses()`

This policy is not based on a GeoIP table; it is built from route-origin/BGP-style sources plus country CIDR zone files.

## Repository Scope

This public repository contains the core script and documentation for public usage.
