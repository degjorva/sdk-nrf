#!/usr/bin/env python3
"""
ADAC Reset Trigger Test Script

This script tests the ADAC reset detection logic by:
1. Testing CTRL-AP reset (should trigger ADAC)
2. Testing pin reset via nrfjprog (should NOT trigger ADAC)

The device should only enter ADAC wait mode after a CTRL-AP reset.

Usage:
    python3 test_adac_reset.py --test ctrlap   # Test CTRL-AP reset (should work)
    python3 test_adac_reset.py --test pinreset # Test pin reset (should NOT work)

Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
"""

import argparse
import subprocess
import time
import sys

try:
    import pylink
except ImportError:
    print("Error: pylink not found. Install with: pip install pylink-square")
    sys.exit(1)


# CTRL-AP configuration
CTRL_AP_INDEX = 2
CTRLAP_RESET = 0x00
CTRLAP_MAILBOX_TXDATA = 0x20
CTRLAP_MAILBOX_TXSTATUS = 0x24
CTRLAP_MAILBOX_RXSTATUS = 0x2C

# DAP register indices
DP_SELECT = 0x08


class CtrlApAccess:
    """Simple CTRL-AP access for testing."""

    def __init__(self, serial_number=None):
        self.jlink = pylink.JLink()
        self.jlink.open(serial_no=serial_number)
        self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        self.jlink.set_speed(4000)

        try:
            self.jlink.connect('CORTEX-M33', verbose=False)
        except pylink.errors.JLinkException:
            pass  # May fail on protected devices

        self.jlink.coresight_configure()
        self.ctrl_ap_num = CTRL_AP_INDEX

    def _read_ap_reg(self, reg_offset):
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (self.ctrl_ap_num << 24) | (ap_bank << 4)
        self.jlink.coresight_write(DP_SELECT >> 2, select_val, ap=False)
        reg_in_bank = reg_offset & 0x0F
        return self.jlink.coresight_read(reg_in_bank >> 2, ap=True)

    def _write_ap_reg(self, reg_offset, value):
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (self.ctrl_ap_num << 24) | (ap_bank << 4)
        self.jlink.coresight_write(DP_SELECT >> 2, select_val, ap=False)
        reg_in_bank = reg_offset & 0x0F
        self.jlink.coresight_write(reg_in_bank >> 2, value, ap=True)

    def close(self):
        if self.jlink:
            self.jlink.close()

    def ctrlap_reset(self):
        """Trigger a soft reset via CTRL-AP."""
        print("  Triggering CTRL-AP soft reset...")
        self._write_ap_reg(CTRLAP_RESET, 0x01)

    def send_trigger_word(self):
        """Send trigger word to mailbox."""
        print("  Sending trigger word 0xADAC0001...")
        self._write_ap_reg(CTRLAP_MAILBOX_TXDATA, 0xADAC0001)

    def wait_for_device_read(self, timeout_s=5):
        """Wait for device to read the trigger word."""
        print(f"  Waiting up to {timeout_s}s for device to read trigger...")
        start = time.time()
        while time.time() - start < timeout_s:
            txstatus = self._read_ap_reg(CTRLAP_MAILBOX_TXSTATUS)
            if not (txstatus & 1):
                elapsed = time.time() - start
                return True, elapsed
            time.sleep(0.1)
        return False, timeout_s


def test_ctrlap_reset():
    """Test that CTRL-AP reset triggers ADAC mode."""
    print("\n" + "="*60)
    print("TEST: CTRL-AP Reset (should trigger ADAC)")
    print("="*60)

    ap = CtrlApAccess()
    try:
        # Reset first, then send trigger (mailbox is cleared on reset)
        ap.ctrlap_reset()
        time.sleep(0.2)  # Wait for device to start booting and reach ADAC check

        # Send trigger word (device is waiting for it with 500ms timeout)
        ap.send_trigger_word()

        # Wait for device to read trigger
        success, elapsed = ap.wait_for_device_read(timeout_s=5)

        if success:
            print(f"\n  ✓ PASS: Device read trigger in {elapsed:.2f}s")
            print("    Device entered ADAC mode")
            return True
        else:
            print(f"\n  ✗ FAIL: Device did NOT read trigger within {elapsed:.2f}s")
            print("    Device may not have reached ADAC check in time")
            return False
    finally:
        ap.close()


def test_pinreset():
    """Test that pin reset does NOT trigger ADAC mode."""
    print("\n" + "="*60)
    print("TEST: Pin Reset via nrfjprog (should NOT trigger ADAC)")
    print("="*60)

    # First trigger a pin reset using nrfjprog
    print("  Triggering pin reset via nrfjprog...")
    try:
        result = subprocess.run(
            ['nrfjprog', '--pinreset'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print(f"  Warning: nrfjprog returned {result.returncode}")
            print(f"  stderr: {result.stderr}")
    except FileNotFoundError:
        print("  Error: nrfjprog not found. Please install nRF Command Line Tools.")
        return None
    except subprocess.TimeoutExpired:
        print("  Error: nrfjprog timed out")
        return None

    time.sleep(0.5)  # Wait for reset

    # Now try to send trigger word
    ap = CtrlApAccess()
    try:
        ap.send_trigger_word()

        # Wait briefly for device to read (should NOT read since it's not in ADAC mode)
        success, elapsed = ap.wait_for_device_read(timeout_s=3)

        if success:
            print(f"\n  ✗ FAIL: Device read trigger in {elapsed:.2f}s")
            print("    Device entered ADAC mode after pin reset (unexpected!)")
            return False
        else:
            print(f"\n  ✓ PASS: Device did NOT read trigger within {elapsed:.2f}s")
            print("    Device correctly ignored ADAC request after pin reset")
            return True
    finally:
        ap.close()


def test_debugreset():
    """Test that debug reset via nrfjprog does NOT trigger ADAC mode."""
    print("\n" + "="*60)
    print("TEST: Debug Reset via nrfjprog (should NOT trigger ADAC)")
    print("="*60)

    # Trigger a debug reset using nrfjprog
    print("  Triggering debug reset via nrfjprog...")
    try:
        result = subprocess.run(
            ['nrfjprog', '--debugreset'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode != 0:
            print(f"  Warning: nrfjprog returned {result.returncode}")
            # Debug reset may fail on protected devices, that's expected
    except FileNotFoundError:
        print("  Error: nrfjprog not found. Please install nRF Command Line Tools.")
        return None
    except subprocess.TimeoutExpired:
        print("  Error: nrfjprog timed out")
        return None

    time.sleep(0.5)  # Wait for reset

    # Now try to send trigger word
    ap = CtrlApAccess()
    try:
        ap.send_trigger_word()

        # Wait briefly for device to read
        success, elapsed = ap.wait_for_device_read(timeout_s=3)

        if success:
            print(f"\n  ? UNCERTAIN: Device read trigger in {elapsed:.2f}s")
            print("    Debug reset may or may not be a CTRL-AP reset depending on implementation")
            return None
        else:
            print(f"\n  ✓ PASS: Device did NOT read trigger within {elapsed:.2f}s")
            print("    Device correctly ignored ADAC request after debug reset")
            return True
    finally:
        ap.close()


def main():
    parser = argparse.ArgumentParser(
        description="Test ADAC reset detection logic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Tests:
    ctrlap    - Test CTRL-AP reset (should trigger ADAC)
    pinreset  - Test pin reset via nrfjprog (should NOT trigger ADAC)
    debugreset - Test debug reset via nrfjprog
    all       - Run all tests

Examples:
    python3 test_adac_reset.py --test ctrlap
    python3 test_adac_reset.py --test pinreset
    python3 test_adac_reset.py --test all
"""
    )

    parser.add_argument(
        '--test', '-t',
        choices=['ctrlap', 'pinreset', 'debugreset', 'all'],
        default='all',
        help='Which test to run'
    )

    args = parser.parse_args()

    results = {}

    if args.test in ['ctrlap', 'all']:
        results['ctrlap'] = test_ctrlap_reset()

    if args.test in ['pinreset', 'all']:
        results['pinreset'] = test_pinreset()

    if args.test in ['debugreset', 'all']:
        results['debugreset'] = test_debugreset()

    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    all_passed = True
    for test_name, result in results.items():
        if result is True:
            status = "✓ PASS"
        elif result is False:
            status = "✗ FAIL"
            all_passed = False
        else:
            status = "? SKIP/UNCERTAIN"
        print(f"  {test_name:15s}: {status}")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
