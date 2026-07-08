# dhcping v1.4f

A small command-line tool for **testing and auditing DHCP servers**. `dhcping`
crafts a raw DHCP packet (DISCOVER, REQUEST, INFORM, LEASEQUERY, ...), sends it
to a server, and reports whether a valid answer came back — optionally decoding
every option in the reply. It's the DHCP equivalent of `ping`: a quick way to
confirm a server is alive and responding the way you expect.

This is a fork of the original [`dhcping`](http://www.mavetju.org) by Edwin
Groothuis (based on v1.3), extended with additional DHCP message types, relay
agent (option 82) and vendor-class (option 60) injection, and much richer
response decoding. See [CHANGES](CHANGES) for the full fork changelog.

> ⚠️ **For DHCP testing and diagnostics only.** Sending DISCOVER/REQUEST traffic
> to a production DHCP server can consume real leases from its pool. Only run
> this against servers you are authorized to test. For passive on-the-wire
> monitoring, use [`dhcpdump`](http://www.mavetju.org) instead.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Building from source](#building-from-source)
- [Prebuilt binaries](#prebuilt-binaries)
- [Usage](#usage)
  - [DHCP message types](#dhcp-message-types)
  - [Options](#options)
- [Examples](#examples)
- [Exit codes](#exit-codes)
- [Verbose output](#verbose-output)
- [Security](#security)
- [Files](#files)
- [License & credits](#license--credits)

---

## Features

- Send any of seven DHCP message types: **DISCOVER, REQUEST, DECLINE, RELEASE,
  INFORM, LEASEQUERY, LEASEACTIVE**.
- Acts as a relay-agent probe — set a `giaddr` and inject **option 82**
  (relay agent remote-id) to test scopes behind a relay.
- Inject **option 60** (vendor class identifier, e.g. `docsis`) for
  vendor-specific server behaviour.
- Automatically **releases the lease** after a successful REQUEST (disable with
  `-n` to keep the lease active).
- **Decodes DHCP responses** in verbose mode — subnet, routers, DNS, lease
  times, server-id, relay-agent sub-options, and CableLabs/PacketCable blocks.
- Meaningful **exit codes** (`0` = answered, `1` = no answer) for use in
  monitoring scripts and health checks.
- Drops root privileges immediately after binding its socket.

## How it works

`dhcping` builds a BOOTP/DHCP packet by hand, sends it over UDP to the target
server, and waits up to `maxwait` seconds for a reply. If a reply arrives from
the expected server it is (optionally) decoded and, for a REQUEST, a
`DHCPRELEASE` is sent back so the test does not permanently consume a lease.

By default (no message-type flag) `dhcping` sends a `DHCPREQUEST`. The
message-type flags `-d`, `-r`, `-l`, `-i`, and `-a` are **mutually exclusive**.

The tool binds to the server port `bootps` (67) for LEASEQUERY, DISCOVER, or
whenever a gateway/relay address is set (relay-agent mode); otherwise it binds
to the client port `bootpc` (68).

## Requirements

- A Unix-like OS (Linux, *BSD, Solaris/SunOS) with a C compiler.
- **Root privileges** (or the binary installed setuid root) — required to bind
  the privileged BOOTP ports and to broadcast.
- For building from source: a C toolchain (`gcc`/`cc`) and `make`. The bundled
  `configure` script is generated with autotools.

## Building from source

The project ships a standard autotools build:

```sh
./configure
make
sudo make install      # installs to /usr/local/bin by default
```

To install into a different location:

```sh
./configure --prefix=/opt/dhcping
make
sudo make install
```

For a quick one-off build without installing, the single C source can be
compiled directly:

```sh
cc -O2 -o dhcping dhcping.c
```

The only source files are [dhcping.c](dhcping.c) and its lookup tables in
[dhcp_options.h](dhcp_options.h).

## Prebuilt binaries

Prebuilt `x86_64` binaries are included for older Red Hat / CentOS releases:

| File | Platform |
|------|----------|
| [dhcping-1.4f-el5-x86_64.tar](dhcping-1.4f-el5-x86_64.tar) | RHEL / CentOS 5 |
| [dhcping-1.4f-el6-x86_64.tar](dhcping-1.4f-el6-x86_64.tar) | RHEL / CentOS 6 |

Each archive contains a single `dhcping` binary:

```sh
tar xf dhcping-1.4f-el6-x86_64.tar
sudo ./dhcping ...
```

## Usage

```
usage: dhcping -c <ciaddr> -g <giaddr> -h <chaddr> -s <server-ip>
```

Run `dhcping` with no arguments to print the built-in help.

### DHCP message types

| Flag | DHCP type | Message |
|------|-----------|---------|
| `-d` | (1)  | DISCOVER |
| `-r` | (3)  | REQUEST *(default)* |
| `-f` | (4)  | DECLINE |
| `-e` | (7)  | RELEASE |
| `-i` | (8)  | INFORM |
| `-l` | (10) | LEASEQUERY *(requests options 51, 60, 61, 82)* |
| `-a` | (13) | LEASEACTIVE |

`-d`, `-r`, `-l`, `-i`, and `-a` cannot be combined with one another.

### Options

| Flag | Argument | Description |
|------|----------|-------------|
| `-c` | `<ciaddr>` | Client IP address (also the address a reply is sent to). |
| `-g` | `<giaddr>` | Gateway / relay agent IP address (`giaddr`). |
| `-h` | `<chaddr>` | Client hardware (MAC) address, e.g. `28:be:9b:ab:50:ce`. Up to 16 colon-separated octets. |
| `-s` | `<server-ip>` | DHCP server IP address to send the packet to. |
| `-p` | `<vendor>` | Option 60 vendor class identifier string (e.g. `docsis`, max 10 chars). |
| `-o` | `<relay-mac>` | Option 82 relay agent remote-id (MAC address of the DHCP relay agent). |
| `-n` | | Keep the lease active after a REQUEST (skip the automatic RELEASE). |
| `-t` | `<maxwait>` | Seconds to wait for an answer (default: `3`). |
| `-v` | | Verbose output — decode the sent and received packets. |
| `-q` | | Quiet — suppress informational messages and warnings. |

Notes:

- A DISCOVER must **not** include a client IP (`-c`).
- A REQUEST really wants a client IP; `dhcping` warns if one is missing.

## Examples

**Liveness check** — is the server answering for this client?

```sh
dhcping -s 10.34.134.215 -c 10.34.134.217 -h 28:be:9b:ab:50:ce
```

Prints `Got answer from: 10.34.134.215` on success, or `NO ANSWER` on timeout.

**DISCOVER** — probe without claiming a specific address:

```sh
dhcping -d -s 10.34.134.215 -h 28:be:9b:ab:50:ce
```

**INFORM** — ask for configuration parameters only:

```sh
dhcping -i -s 10.34.134.215 -c 10.34.134.217 -h 28:be:9b:ab:50:ce
```

**LEASEQUERY** (verbose) — query the server for a lease, via a relay address:

```sh
dhcping -v -l -h 28:be:9b:ab:50:ce -g 10.34.134.217 -s 10.34.134.215
```

**REQUEST without auto-release** — leave the lease in place afterwards:

```sh
dhcping -r -n -s 10.34.134.215 -c 10.34.134.217 -h 28:be:9b:ab:50:ce
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | A valid answer was received from the server. |
| `1` | No answer within the timeout. |

This makes `dhcping` easy to wire into monitoring — e.g. a Nagios/Icinga check
or a cron-based health probe.

## Verbose output

With `-v`, `dhcping` prints the decoded DHCP header and every option it
understands in the response, including:

- Subnet mask, routers, time/name/DNS/log servers, domain name, NTP servers
- Lease time, renewal/rebinding timers (rendered as `weeks/days/hours/min/sec`;
  a 365-day value is shown as `Lease reserved`)
- DHCP message type, server identifier, requested IP, client identifier
- TFTP server and boot file name
- Relay Agent (option 82) circuit-id / remote-id sub-options
- CableLabs / PacketCable client-configuration blocks and lease-query results

For general packet capture on the wire, prefer `dhcpdump`.

## Security

`dhcping` needs root to bind the privileged BOOTP ports (67/68) and to enable
broadcast. It should be run by root or installed **setuid root**; root
privileges are dropped back to the calling user immediately after the socket is
bound. Install setuid only on trusted, controlled hosts.

## Files

| Path | Description |
|------|-------------|
| [dhcping.c](dhcping.c) | Main source. |
| [dhcp_options.h](dhcp_options.h) | Lookup tables for DHCP option and message-type names. |
| [dhcping.pod](dhcping.pod) / [dhcping.8](dhcping.8) | Man page (POD source and generated `man` page). |
| [CHANGES](CHANGES) | Version history / fork changelog. |
| [LICENSE](LICENSE) | BSD 2-clause license. |
| [CONTACT](CONTACT) | Original author contact details. |

## License & credits

Distributed under the **BSD 2-clause license** — see [LICENSE](LICENSE).

Copyright © 2000–2002 Edwin Groothuis `<edwin@mavetju.org>`
(<http://www.mavetju.org>). Fork and v1.4f modifications by
`<nean.and.i@gmail.com>`.

**See also:** `dhcpd(8)`, `dhclient(8)`, `dhcpd.conf(5)`, `dhcpdump(8)`.
