# ARP Spoofer (MITM) — Python + Scapy

A command-line ARP spoofing tool that positions the host running it as a
man-in-the-middle (MITM) between a target machine and its gateway. Built with
[Scapy](https://scapy.net/) for hands-on study of layer-2 attacks and network
defense.

> **For authorized security testing and education only.** See the
> [Legal / Ethical Use](#legal--ethical-use) section before running anything.

---

## Table of Contents

- [What It Does](#what-it-does)
- [Networking Theory (ARP + MITM)](#networking-theory-arp--mitm)
- [Architecture & Flow](#architecture--flow)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [Legal / Ethical Use](#legal--ethical-use)
- [What I Learned / Skills Demonstrated](#what-i-learned--skills-demonstrated)
- [License](#license)

---

## What It Does

The tool continuously sends forged ARP replies to two hosts — a **target**
(victim) and the **gateway** (router) — telling each that the *other's* IP
address is located at the attacker's MAC address. Both hosts update their ARP
caches accordingly and start sending their traffic to the attacker, who then
forwards it on so the connection appears normal.

Key properties:

- **No hardcoded values** — target, gateway, and interface are all CLI flags.
- **Gateway auto-detection** from the system routing table when `-g` is omitted.
- **Automatic IP forwarding** — enabled on start, restored to its original
  value on exit, so intercepted traffic still reaches its destination.
- **Clean teardown** — on `Ctrl+C` it re-ARPs both hosts with their correct
  MACs, healing the poisoned caches and leaving the network as it was found.
- **Does not capture, inspect, log, or store any intercepted traffic.** It
  performs the ARP poisoning only. Traffic analysis is deliberately out of scope.

---

## Networking Theory (ARP + MITM)

**ARP (Address Resolution Protocol)** maps a layer-3 IP address to a layer-2
MAC address on a local network. When host A wants to talk to IP `X`, it
broadcasts *"who has X?"*; the owner of `X` replies *"X is at MAC yy:yy:..."*.
Host A caches that answer.

The weakness: classic ARP is **stateless and unauthenticated**. A host will
accept an ARP reply even if it never asked, and will happily overwrite its
cache. This is called **ARP cache poisoning**.

**The MITM position:** by poisoning the caches of *both* the target and the
gateway, the attacker makes:

- the **target** believe the *gateway's* IP is at the attacker's MAC, and
- the **gateway** believe the *target's* IP is at the attacker's MAC.

Now all traffic between them flows *through* the attacker. With IP forwarding
enabled, the attacker relays packets to their true destination, so neither side
notices a disruption — the definition of a man-in-the-middle.

---

## Architecture & Flow

```
                 ARP poisoning (forged replies, every 2s)
                 ┌───────────────────────────────────────┐
                 ▼                                         ▼
        ┌─────────────────┐                       ┌─────────────────┐
        │     TARGET      │                       │     GATEWAY     │
        │  192.168.1.10   │                       │  192.168.1.1    │
        │ cache: GW is at │                       │ cache: TGT is at│
        │  ATTACKER_MAC   │                       │  ATTACKER_MAC   │
        └───────┬─────────┘                       └────────┬────────┘
                │                                          │
                │      real traffic redirected here        │
                └──────────────►  ┌───────────────┐ ◄──────┘
                                  │   ATTACKER    │
                                  │ (this script) │
                                  │ IP forwarding │
                                  │   = enabled   │
                                  └───────────────┘
                              relays packets to real dest
```

**Program flow:**

```
main()
  ├─ parse_args()             # -t/-g/-i/-v/--i-am-authorized (argparse)
  ├─ configure_logging()      # logging module, DEBUG/INFO
  ├─ print banner + disclaimer
  ├─ require_root()           # exit if not root
  ├─ confirm_authorization()  # flag or interactive confirmation
  ├─ detect_gateway()         # if -g not supplied
  ├─ resolve_or_exit()  ×2    # get_mac(target), get_mac(gateway) — validated
  ├─ enable_ip_forwarding()   # capture original value
  └─ loop:
       spoof(target ← gateway)
       spoof(gateway ← target)
       sleep(SLEEP_INTERVAL_SECONDS)
     on Ctrl+C / exit (finally):
       restore(target, gateway)      # heal ARP caches
       restore(gateway, target)
       restore_ip_forwarding()       # back to original
```

---

## Installation

Requires **Python 3.9+**, **Linux** (for automatic IP-forwarding management),
and **root** privileges.

```bash
# 1. Clone
git clone https://github.com/dannyj1202/ARP-Spoofer---Ethical-Hacking-Project.git
cd ARP-Spoofer---Ethical-Hacking-Project

# 2. (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Make the script executable (optional)
chmod +x arp_spoofer.py
```

---

## Usage

```
sudo ./arp_spoofer.py -t TARGET [-g GATEWAY] [-i INTERFACE] [-v] --i-am-authorized
```

| Flag | Long form | Required | Description |
|------|-----------|----------|-------------|
| `-t` | `--target` | yes | Target (victim) IP address |
| `-g` | `--gateway` | no | Gateway IP (auto-detected if omitted) |
| `-i` | `--interface` | no | Interface to use, e.g. `eth0`, `wlan0` |
| `-v` | `--verbose` | no | Enable DEBUG logging |
|      | `--i-am-authorized` | no* | Skip the interactive authorization prompt |

\* If `--i-am-authorized` is not passed, the tool prompts for confirmation
before doing anything.

**Examples:**

```bash
# Auto-detect the gateway, confirm authorization interactively
sudo ./arp_spoofer.py -t 192.168.1.10

# Specify everything explicitly, verbose, non-interactive
sudo ./arp_spoofer.py -t 192.168.1.10 -g 192.168.1.1 -i eth0 -v --i-am-authorized
```

---

## Sample Output

> Illustrative output using synthetic addresses.

```
+--------------------------------------------------------------+
|                      ARP Spoofer (MITM)                      |
|          For AUTHORIZED security testing ONLY                |
+--------------------------------------------------------------+

LEGAL / ETHICAL NOTICE
This tool poisons ARP caches to intercept traffic. Running it against
hosts or networks you do not own or lack written authorization to test
is illegal in most jurisdictions. ...

14:12:03 [INFO] Target : 192.168.1.10
14:12:03 [INFO] Gateway: 192.168.1.1
14:12:04 [INFO] Poisoning started. Press Ctrl+C to stop and restore.
[+] Packets sent: 42
^C
14:12:25 [INFO] Ctrl+C detected. Restoring ARP tables...
14:12:26 [INFO] Network restored. Exiting cleanly.
```

Error handling examples:

```
$ ./arp_spoofer.py -t 192.168.1.10
14:20:01 [ERROR] Root privileges are required ... Re-run with: sudo arp_spoofer.py ...

$ sudo ./arp_spoofer.py -t 999.999.1.1
error: argument -t/--target: '999.999.1.1' is not a valid IP address

$ sudo ./arp_spoofer.py -t 192.168.1.250 --i-am-authorized
14:21:10 [ERROR] Could not resolve a MAC for the target (192.168.1.250).
                 Is it online and on the same subnet as this machine?
```

---

## Legal / Ethical Use

ARP spoofing intercepts other people's network traffic. Using it against any
network, host, or device that you do not **own** or have **explicit written
authorization** to test is illegal in most jurisdictions and unethical.

This project exists to help understand how the attack works so it can be
**detected and defended against** (e.g. dynamic ARP inspection, static ARP
entries, port security, encrypted transport). Use it only in:

- a personal home lab / isolated virtual network you control, or
- a professional engagement with signed authorization (scope + permission).

You are solely responsible for how you use this tool. The author accepts no
liability for misuse. Built-in safeguards (root check, authorization
confirmation, no traffic storage) are deterrents, **not** legal cover.

---

## What I Learned / Skills Demonstrated

- **Networking fundamentals:** ARP resolution, layer-2 vs layer-3 addressing,
  cache poisoning, and how a MITM position is established and torn down.
- **Packet crafting with Scapy:** building and sending `ARP`/`Ether` frames,
  reading answered/unanswered pairs from `srp`, and querying the routing table.
- **Defensive-minded engineering:** clean teardown that restores the network to
  its original state, and a deliberate decision *not* to capture traffic.
- **Professional Python:** `argparse` CLI design, type hints, docstrings, the
  `logging` module, input validation with `ipaddress`, constants over magic
  numbers, and a `main()` guarded entry point.
- **Robustness:** retry logic, `None`-safe MAC resolution (no `IndexError`),
  graceful failure with clear messages and non-zero exit codes, and
  `try/finally` cleanup guarantees.
- **System interaction:** privilege checks and safe toggling/restoration of
  Linux IP forwarding via `/proc`.

---

## License

Copyright (c) 2026 dannyj1202. Released under the [MIT License](LICENSE) with an
additional educational-use notice. See the `LICENSE` file for details.

> The "MIT" in *MIT License* refers to the permissive open-source license that
> originated at the Massachusetts Institute of Technology; it implies no
> affiliation with the institution and is free for anyone to apply to their own
> work.
