wg-ipv6-converter
===

Converts and adds IPv4- to IPv6-Adresses and AllowedIP-Entries for wireguard-interfaces.

<br>

<!-- TOC -->
- [1. Overview](#1-overview)
- [2. Install](#2-install)
    - [2.1. From Binary](#21-from-binary)
    - [2.2. From sources](#22-from-sources)
- [3. Setup](#3-setup)
    - [3.1. Environment](#31-environment)
    - [3.2. Examples](#32-examples)
- [4. License](#4-license)
<!-- /TOC -->

<br>

# 1. Overview

The program will convert IPv4-only wireguard-interfaces to IPv6. It converts and adds the Address of the Interface and AllowedIPs-Entries with optional filters.

IPv6-Adresses are generated based on the IPv4-Adress.

Beware: This program needs `NET_ADMIN` privileges for setting Adresses and to access the wireguard-daemon.

<br>

# 2. Install

## 2.1. From Binary

1. Download the appripriate binary for your system from the Release-page (or build from sources)
2. Save at an appropriate location e.g. `/usr/bin/local/wg-ipv6-converter`
3. Make executeable: `chmod +x /usr/bin/local/wg-ipv6-converter`

<br>

## 2.2. From sources

Clone the repository and compile using `go build ./cmd/app`

<br>

# 3. Setup
## 3.1. Environment

Variable|Description|Default
-|-|-
`INTERFACE`*        | Wireguard-Interface Name                  |
`IPV6_FORMAT`       | Format to use for converting v4 to v6 <br> The CIDR-Mask gets translated using 128 - 24 - Mask <br> e.g. `10.0.100.5/16` -> `fc12::0a00:6405/96`   | `fc12::%02x%02x:%02x%02x/%d`
`FILTER_PREFIX`     | Prefix to filter for IP-Networks          | `100.100`
`RECHECK_INTERVAL`  | Interval in go-time-format to recheck AllowedIPs entries in case something changed  | 5m

*\* Required*

<br>

## 3.2. Examples

### 3.2.1.  Netbird

Netbird is at the moment only IPv4-compatible, with this program running where necessary, some basic IPv6-setup can be archieved.

```bash
INTERFACE="wt0" ./wg-ipv6-converter
```
Or using a systemd-service based on the example:
```bash
[Unit]
Description=WireGuard IPv6 converter for netbird
BindsTo=netbird.service
After=netbird.service

[Service]
Type=simple
ExecStartPre=/bin/sleep 10
ExecStart=/usr/local/bin/wg-ipv6-converter
Restart=always
RestartSec=30

Environment="INTERFACE=wt0"
Environment="RECHECK_INTERVAL=60s"

[Install]
WantedBy=multi-user.target
```

<br>

# 4. License

This project is licenced under GPLv3.  
See [LICENSE](LICENSE) for more details.
