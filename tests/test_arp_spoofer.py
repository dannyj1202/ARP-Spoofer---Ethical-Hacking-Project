"""Unit tests for arp_spoofer.

Scapy is fully mocked (see conftest.py), so these tests never touch the network
and never send a single packet. They exercise the pure logic: input validation,
argument parsing, MAC resolution, gateway detection, spoof/restore packet
construction, privilege checks, and IP-forwarding management.

Run with:  pytest -v
"""

from __future__ import annotations

import argparse
from unittest.mock import MagicMock, mock_open, patch

import pytest

import arp_spoofer


@pytest.fixture(autouse=True)
def reset_scapy():
    """Reset the shared Scapy mock between tests for isolation."""
    arp_spoofer.scapy.reset_mock(return_value=True, side_effect=True)
    yield


def _answered_pair(mac: str):
    """Build a fake Scapy answered-list entry whose reply has hwsrc == mac."""
    received = MagicMock()
    received.hwsrc = mac
    sent = MagicMock()
    return [(sent, received)]


# --------------------------------------------------------------------------- #
# valid_ip
# --------------------------------------------------------------------------- #
class TestValidIp:
    def test_accepts_ipv4(self):
        assert arp_spoofer.valid_ip("192.168.1.10") == "192.168.1.10"

    def test_accepts_ipv6(self):
        assert arp_spoofer.valid_ip("::1") == "::1"

    @pytest.mark.parametrize("bad", ["999.999.1.1", "not-an-ip", "192.168.1", ""])
    def test_rejects_malformed(self, bad):
        with pytest.raises(argparse.ArgumentTypeError):
            arp_spoofer.valid_ip(bad)


# --------------------------------------------------------------------------- #
# parse_args
# --------------------------------------------------------------------------- #
class TestParseArgs:
    def test_defaults(self):
        args = arp_spoofer.parse_args(["-t", "192.168.1.10"])
        assert args.target == "192.168.1.10"
        assert args.gateway is None
        assert args.interface is None
        assert args.verbose is False
        assert args.i_am_authorized is False

    def test_all_flags(self):
        args = arp_spoofer.parse_args(
            ["-t", "192.168.1.10", "-g", "192.168.1.1",
             "-i", "eth0", "-v", "--i-am-authorized"]
        )
        assert args.gateway == "192.168.1.1"
        assert args.interface == "eth0"
        assert args.verbose is True
        assert args.i_am_authorized is True

    def test_target_is_required(self):
        with pytest.raises(SystemExit):
            arp_spoofer.parse_args([])

    def test_invalid_ip_rejected(self):
        with pytest.raises(SystemExit):
            arp_spoofer.parse_args(["-t", "999.999.1.1"])


# --------------------------------------------------------------------------- #
# get_mac
# --------------------------------------------------------------------------- #
class TestGetMac:
    def test_returns_mac_on_answer(self):
        arp_spoofer.scapy.srp.return_value = (_answered_pair("aa:bb:cc:dd:ee:ff"), [])
        assert arp_spoofer.get_mac("192.168.1.1") == "aa:bb:cc:dd:ee:ff"

    def test_returns_none_when_no_answer(self):
        arp_spoofer.scapy.srp.return_value = ([], [])
        assert arp_spoofer.get_mac("192.168.1.250", retries=2) is None

    def test_retries_until_exhausted(self):
        arp_spoofer.scapy.srp.return_value = ([], [])
        arp_spoofer.get_mac("192.168.1.250", retries=3)
        assert arp_spoofer.scapy.srp.call_count == 3


# --------------------------------------------------------------------------- #
# resolve_or_exit
# --------------------------------------------------------------------------- #
class TestResolveOrExit:
    def test_returns_mac(self):
        with patch.object(arp_spoofer, "get_mac", return_value="aa:bb:cc:dd:ee:ff"):
            assert arp_spoofer.resolve_or_exit("192.168.1.1", "gateway") == "aa:bb:cc:dd:ee:ff"

    def test_exits_when_unreachable(self):
        with patch.object(arp_spoofer, "get_mac", return_value=None):
            with pytest.raises(SystemExit) as exc:
                arp_spoofer.resolve_or_exit("192.168.1.250", "target")
        assert exc.value.code == arp_spoofer.EXIT_ERROR


# --------------------------------------------------------------------------- #
# detect_gateway
# --------------------------------------------------------------------------- #
class TestDetectGateway:
    def test_returns_gateway(self):
        arp_spoofer.scapy.conf.route.route.return_value = ("eth0", "192.168.1.50", "192.168.1.1")
        assert arp_spoofer.detect_gateway() == "192.168.1.1"

    def test_returns_none_for_zero_route(self):
        arp_spoofer.scapy.conf.route.route.return_value = ("eth0", "0.0.0.0", "0.0.0.0")
        assert arp_spoofer.detect_gateway() is None

    def test_returns_none_on_exception(self):
        arp_spoofer.scapy.conf.route.route.side_effect = RuntimeError("no route")
        assert arp_spoofer.detect_gateway() is None


# --------------------------------------------------------------------------- #
# spoof / restore
# --------------------------------------------------------------------------- #
class TestSpoofRestore:
    def test_spoof_sends_one_packet(self):
        arp_spoofer.spoof("192.168.1.10", "aa:bb:cc:dd:ee:ff", "192.168.1.1", None)
        arp_spoofer.scapy.send.assert_called_once()

    def test_restore_sends_correction_packets(self):
        with patch.object(arp_spoofer, "get_mac", return_value="aa:bb:cc:dd:ee:ff"):
            arp_spoofer.restore("192.168.1.10", "192.168.1.1", None)
        arp_spoofer.scapy.send.assert_called_once()
        _, kwargs = arp_spoofer.scapy.send.call_args
        assert kwargs["count"] == arp_spoofer.RESTORE_PACKET_COUNT

    def test_restore_skips_send_when_host_offline(self):
        with patch.object(arp_spoofer, "get_mac", return_value=None):
            arp_spoofer.restore("192.168.1.10", "192.168.1.1", None)
        arp_spoofer.scapy.send.assert_not_called()


# --------------------------------------------------------------------------- #
# confirm_authorization
# --------------------------------------------------------------------------- #
class TestConfirmAuthorization:
    def test_flag_bypasses_prompt(self):
        with patch("builtins.input") as mocked_input:
            arp_spoofer.confirm_authorization(True)
        mocked_input.assert_not_called()

    def test_correct_answer_passes(self):
        with patch("builtins.input", return_value="I am authorized"):
            arp_spoofer.confirm_authorization(False)  # should not raise

    def test_wrong_answer_exits(self):
        with patch("builtins.input", return_value="nope"):
            with pytest.raises(SystemExit):
                arp_spoofer.confirm_authorization(False)


# --------------------------------------------------------------------------- #
# root checks
# --------------------------------------------------------------------------- #
class TestRootChecks:
    def test_is_root_true(self):
        with patch("os.geteuid", return_value=0, create=True):
            assert arp_spoofer.is_root() is True

    def test_is_root_false(self):
        with patch("os.geteuid", return_value=1000, create=True):
            assert arp_spoofer.is_root() is False

    def test_require_root_exits_when_not_root(self):
        with patch.object(arp_spoofer, "is_root", return_value=False):
            with pytest.raises(SystemExit):
                arp_spoofer.require_root()


# --------------------------------------------------------------------------- #
# IP forwarding
# --------------------------------------------------------------------------- #
class TestIpForwarding:
    def test_enable_on_linux_reads_and_writes(self):
        m = mock_open(read_data="0\n")
        with patch("platform.system", return_value="Linux"), patch("builtins.open", m):
            original = arp_spoofer.enable_ip_forwarding()
        assert original == "0"
        m().write.assert_any_call("1\n")

    def test_enable_on_non_linux_returns_none(self):
        with patch("platform.system", return_value="Darwin"), patch("builtins.open") as opened:
            assert arp_spoofer.enable_ip_forwarding() is None
        opened.assert_not_called()

    def test_restore_none_is_noop(self):
        with patch("builtins.open") as opened:
            arp_spoofer.restore_ip_forwarding(None)
        opened.assert_not_called()

    def test_restore_writes_original_on_linux(self):
        m = mock_open()
        with patch("platform.system", return_value="Linux"), patch("builtins.open", m):
            arp_spoofer.restore_ip_forwarding("0")
        m().write.assert_called_once_with("0\n")
