#!/usr/bin/env python3
"""
ADAC Host Script for nRF54L15

This script communicates with the nRF54L15 device via the CTRL-AP mailbox
to perform ADAC (Authenticated Debug Access Control) authentication.

Uses pylink for direct DAP access to the CTRL-AP when device is protected.

Requirements:
    - pylink-square (pip install pylink-square)
    - cryptography (pip install cryptography)

Usage:
    1. Generate certificates: python3 adac_cert.py output/
    2. Flash the firmware with matching ROTPK
    3. Run authentication: python3 adac_host.py --key output/private-key.pem

Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
"""

import argparse
import os
import struct
import time
from pathlib import Path

try:
    import pylink
except ImportError:
    print("Error: pylink not found. Install with: pip install pylink-square")
    exit(1)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# ============================================================================
# ADAC Protocol Constants
# ============================================================================

# Commands (must match adac_commands_t in psa-adac)
ADAC_DISCOVERY_CMD = 0x01
ADAC_AUTH_START_CMD = 0x02
ADAC_AUTH_RESPONSE_CMD = 0x03
ADAC_CLOSE_SESSION_CMD = 0x04
ADAC_RESUME_CMD = 0x05
ADAC_LOCK_DEBUG_CMD = 0x06
ADAC_LCS_CHANGE_CMD = 0x100

# Status codes
ADAC_SUCCESS = 0x0000
ADAC_FAILURE = 0x0001
ADAC_NEED_MORE_DATA = 0x0002
ADAC_UNSUPPORTED = 0x0003
ADAC_UNAUTHORIZED = 0x0004
ADAC_INVALID_PARAMETERS = 0x0005
ADAC_INVALID_COMMAND = 0x7FFF

STATUS_NAMES = {
    ADAC_SUCCESS: "SUCCESS",
    ADAC_FAILURE: "FAILURE",
    ADAC_NEED_MORE_DATA: "NEED_MORE_DATA",
    ADAC_UNSUPPORTED: "UNSUPPORTED",
    ADAC_UNAUTHORIZED: "UNAUTHORIZED",
    ADAC_INVALID_PARAMETERS: "INVALID_PARAMETERS",
    ADAC_INVALID_COMMAND: "INVALID_COMMAND",
}

# Type IDs for TLV
PSA_BINARY_CRT = 0x0201
PSA_BINARY_TOKEN = 0x0200

# Key types
CRYPTOSYSTEM_ID_ED_25519_SHA512 = 0x05

# Certificate constants
ADAC_MAJOR_VERSION = 1
ADAC_MINOR_VERSION = 0
ADAC_ROLE_ROOT = 0x1
ADAC_USAGE_NEUTRAL = 0x0
PSA_LIFECYCLE_UNKNOWN = 0x0000

EDDSA_ED25519_PUBLIC_KEY_SIZE = 32
EDDSA_ED25519_SIGNATURE_SIZE = 64
EDDSA_ED25519_HASH_SIZE = 64

# CTRL-AP configuration
# The CTRL-AP on nRF54L is AP index 2
CTRL_AP_INDEX = 2

# CTRL-AP Debugger-side registers (from Nordic PS documentation)
# https://docs.nordicsemi.com/bundle/ps_nrf54L15/page/ctrl-ap.html
#
# From DEBUGGER perspective:
#   - TXDATA: Debugger writes here, device reads via RXDATA
#   - RXDATA: Device writes here, debugger reads
#
CTRLAP_RESET = 0x00

# Reset types for CTRLAP_RESET register (from nrf_ctrlap.h)
CTRLAP_RESET_NONE = 0x00  # No reset
CTRLAP_RESET_SOFT = 0x01  # Soft reset
CTRLAP_RESET_HARD = 0x02  # Hard reset (full system reset)
CTRLAP_RESET_PIN = 0x03   # Pin reset
CTRLAP_ERASEALL = 0x04
CTRLAP_ERASEALLSTATUS = 0x08
CTRLAP_ERASEPROTECT_STATUS = 0x0C
CTRLAP_ERASEPROTECT_DISABLE = 0x10
CTRLAP_APPROTECT_STATUS = 0x14      # 0x03 means APPROTECT enabled
CTRLAP_MAILBOX_TXDATA = 0x20        # Debugger writes -> Device reads
CTRLAP_MAILBOX_TXSTATUS = 0x24      # 1 = device hasn't read our data yet
CTRLAP_MAILBOX_RXDATA = 0x28        # Device writes -> Debugger reads
CTRLAP_MAILBOX_RXSTATUS = 0x2C      # 1 = device has sent data for us
CTRLAP_INFO_PARTNO = 0x30
CTRLAP_INFO_HWREVISION = 0x34
CTRLAP_IDR = 0xFC


# ============================================================================
# CTRL-AP Mailbox Communication via pyOCD
# ============================================================================

class CtrlApMailbox:
    """
    Handles communication with the device via CTRL-AP mailbox.

    Uses pylink (Segger J-Link SDK) for direct DAP access to the CTRL-AP.
    """

    # CORESIGHT DAP register indices
    DP_IDCODE = 0x00
    DP_CTRL_STAT = 0x04
    DP_SELECT = 0x08
    DP_RDBUFF = 0x0C

    # AP register offsets
    AP_CSW = 0x00
    AP_TAR = 0x04
    AP_DRW = 0x0C
    AP_IDR = 0xFC

    def __init__(self, serial_number=None, verbose=False, extra_verbose=False):
        self.verbose = verbose
        self.extra_verbose = extra_verbose  # For TXSTATUS/RXSTATUS polling
        self.jlink = None

        print("Connecting via J-Link...")

        self.jlink = pylink.JLink()
        self.jlink.open(serial_no=serial_number)

        print(f"Using probe: {self.jlink.product_name} (S/N: {self.jlink.serial_number})")

        # Set target interface to SWD
        self.jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)

        # Set speed
        self.jlink.set_speed(4000)  # 4 MHz

        # Connect to target - use CORTEX-M33 as generic target
        try:
            self.jlink.connect('CORTEX-M33', verbose=verbose)
            print("Connected to target")
            self.target_connected = True
        except pylink.errors.JLinkException as e:
            print(f"Note: Target connect returned: {e}")
            self.target_connected = False

        # If target connect failed, try to manually initialize SWD
        if not self.target_connected:
            print("Attempting manual SWD initialization...")
            self._manual_swd_init()

        # Configure CoreSight
        print("Configuring CoreSight...")
        self.jlink.coresight_configure()

        # Initialize CTRL-AP access
        self.ctrl_ap_num = CTRL_AP_INDEX  # CTRL-AP is typically AP2 on nRF

        # Try to read CTRL-AP IDR to verify access
        print(f"Accessing CTRL-AP (AP{self.ctrl_ap_num})...")
        try:
            idr = self._read_ap_reg(self.AP_IDR)
            print(f"CTRL-AP IDR: 0x{idr:08x}")
        except Exception as e:
            print(f"Warning: Could not read CTRL-AP IDR: {e}")

        # Scan ALL APs to find the mailbox
        if verbose:
            print("\nScanning ALL Access Ports...")
            for ap in range(8):
                # Save current AP setting
                old_ap = self.ctrl_ap_num
                self.ctrl_ap_num = ap
                try:
                    idr = self._read_ap_reg(self.AP_IDR)
                    if idr != 0 and idr != 0xFFFFFFFF:
                        print(f"\n  AP{ap}: IDR=0x{idr:08x}")
                        # Scan first few registers
                        for offset in [0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C]:
                            try:
                                val = self._read_ap_reg(offset)
                                if val != 0:
                                    print(f"    Reg 0x{offset:02x}: 0x{val:08x}")
                            except:
                                pass
                except:
                    pass
                self.ctrl_ap_num = old_ap

            # Back to AP2 for now
            self.ctrl_ap_num = CTRL_AP_INDEX
            print(f"\nUsing AP{self.ctrl_ap_num} for CTRL-AP")

        print("CTRL-AP mailbox ready")

    def _manual_swd_init(self):
        """Manually initialize SWD interface when target connect fails."""
        try:
            # Try to read DPIDR via raw SWD
            # This should work even on protected devices
            self._log("Reading DPIDR...")

            # Power up debug domain via CTRL/STAT
            # CSYSPWRUPREQ | CDBGPWRUPREQ
            self.jlink.swd_write32(self.DP_CTRL_STAT >> 2, 0x50000000)
            time.sleep(0.1)

            # Read back and check power bits
            ctrl_stat = self.jlink.swd_read32(self.DP_CTRL_STAT >> 2)
            self._log(f"CTRL/STAT: 0x{ctrl_stat:08x}")

            if not (ctrl_stat & 0xA0000000):
                print("Warning: Debug power-up may have failed")

        except Exception as e:
            self._log(f"Manual SWD init error: {e}")

    def _select_ap(self, ap_num):
        """Select an Access Port via DP SELECT register."""
        # SELECT register: APSEL[31:24], APBANKSEL[7:4]
        select_val = (ap_num << 24)
        self.jlink.coresight_write(self.DP_SELECT >> 2, select_val, ap=False)

    def _read_ap_reg(self, reg_offset):
        """Read an AP register."""
        # Select the AP and bank
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (self.ctrl_ap_num << 24) | (ap_bank << 4)
        self.jlink.coresight_write(self.DP_SELECT >> 2, select_val, ap=False)

        # Read the AP register (reg within bank)
        reg_in_bank = reg_offset & 0x0F
        value = self.jlink.coresight_read(reg_in_bank >> 2, ap=True)

        return value

    def _write_ap_reg(self, reg_offset, value):
        """Write an AP register."""
        # Select the AP and bank
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (self.ctrl_ap_num << 24) | (ap_bank << 4)
        self.jlink.coresight_write(self.DP_SELECT >> 2, select_val, ap=False)

        # Write the AP register
        reg_in_bank = reg_offset & 0x0F
        self.jlink.coresight_write(reg_in_bank >> 2, value, ap=True)

    def close(self):
        if self.jlink:
            self.jlink.close()

    def _log(self, msg):
        if self.verbose:
            print(f"[CTRL-AP] {msg}")

    def _log_poll(self, msg):
        """Log polling status - only in extra verbose mode."""
        if self.extra_verbose:
            print(f"[CTRL-AP] {msg}")

    def _read_mailbox_reg(self, reg_offset):
        """Read a CTRL-AP mailbox register (direct AP register access)."""
        # CTRL-AP registers are direct AP registers, not memory-mapped
        return self._read_ap_reg(reg_offset)

    def _write_mailbox_reg(self, reg_offset, value):
        """Write a CTRL-AP mailbox register (direct AP register access)."""
        # CTRL-AP registers are direct AP registers, not memory-mapped
        self._write_ap_reg(reg_offset, value)

    def wait_for_rx_ready(self, timeout_ms=10000):
        """Wait for device to have data ready for us to read.

        RXSTATUS = 1 means device has written data to RXDATA for us to read.
        """
        start = time.time()
        poll_count = 0
        while (time.time() - start) * 1000 < timeout_ms:
            try:
                status = self._read_mailbox_reg(CTRLAP_MAILBOX_RXSTATUS)
                self._log_poll(f"RXSTATUS: 0x{status:08x}")
                if status & 0x01:  # DataPending - device has data for us
                    return True
                poll_count += 1
                if self.verbose and not self.extra_verbose and poll_count % 20 == 0:
                    print(".", end="", flush=True)
            except Exception as e:
                self._log(f"Read error: {e}")
            time.sleep(0.05)
        return False

    def wait_for_tx_ready(self, timeout_ms=5000, force=False):
        """Wait for device to be ready to receive our data.

        TXSTATUS = 0 means device has read our previous data, we can send more.
        """
        if force:
            return True
        start = time.time()
        poll_count = 0
        while (time.time() - start) * 1000 < timeout_ms:
            try:
                status = self._read_mailbox_reg(CTRLAP_MAILBOX_TXSTATUS)
                self._log_poll(f"TXSTATUS: 0x{status:08x}")
                if not (status & 0x01):  # NoDataPending - device read our data
                    return True
                poll_count += 1
            except Exception as e:
                self._log(f"Read error: {e}")
            time.sleep(0.01)
        return False

    def read_word(self):
        """Read a 32-bit word from device (via RXDATA)."""
        if not self.wait_for_rx_ready():
            raise TimeoutError("Timeout waiting for data from device")
        word = self._read_mailbox_reg(CTRLAP_MAILBOX_RXDATA)
        self._log(f"RX: 0x{word:08x}")
        return word

    def write_word(self, word, force=False):
        """Write a 32-bit word to device (via TXDATA)."""
        if not self.wait_for_tx_ready(force=force):
            raise TimeoutError("Timeout waiting for device to be ready")
        self._log(f"TX: 0x{word:08x}")
        self._write_mailbox_reg(CTRLAP_MAILBOX_TXDATA, word)

    def dump_mailbox_state(self):
        """Dump current mailbox register state for debugging."""
        print("\n[Mailbox State - Debugger Perspective]")
        print("  (TXDATA/TXSTATUS = debugger->device, RXDATA/RXSTATUS = device->debugger)")
        try:
            txdata = self._read_mailbox_reg(CTRLAP_MAILBOX_TXDATA)
            print(f"  TXDATA   (0x{CTRLAP_MAILBOX_TXDATA:02x}): 0x{txdata:08x}  [we write, device reads]")
        except Exception as e:
            print(f"  TXDATA: Error - {e}")
        try:
            txstatus = self._read_mailbox_reg(CTRLAP_MAILBOX_TXSTATUS)
            pending = "DataPending (device hasn't read)" if txstatus & 1 else "NoDataPending (device read it)"
            print(f"  TXSTATUS (0x{CTRLAP_MAILBOX_TXSTATUS:02x}): 0x{txstatus:08x}  [{pending}]")
        except Exception as e:
            print(f"  TXSTATUS: Error - {e}")
        try:
            rxdata = self._read_mailbox_reg(CTRLAP_MAILBOX_RXDATA)
            print(f"  RXDATA   (0x{CTRLAP_MAILBOX_RXDATA:02x}): 0x{rxdata:08x}  [device writes, we read]")
        except Exception as e:
            print(f"  RXDATA: Error - {e}")
        try:
            rxstatus = self._read_mailbox_reg(CTRLAP_MAILBOX_RXSTATUS)
            pending = "DataPending (device sent data)" if rxstatus & 1 else "NoDataPending (no data)"
            print(f"  RXSTATUS (0x{CTRLAP_MAILBOX_RXSTATUS:02x}): 0x{rxstatus:08x}  [{pending}]")
        except Exception as e:
            print(f"  RXSTATUS: Error - {e}")

    def send_request(self, command, data=None):
        """Send a request packet to the device."""
        if data is None:
            data = b''

        # Pad data to word boundary
        while len(data) % 4 != 0:
            data += b'\x00'

        data_count = len(data) // 4

        # Build request header: reserved(2) + command(2) + data_count(4)
        header = struct.pack('<HHI', 0, command, data_count)

        print(f"\n>>> Sending command 0x{command:04x} with {data_count} data words")

        # Send header (2 words)
        self.write_word(struct.unpack('<I', header[0:4])[0])
        self.write_word(struct.unpack('<I', header[4:8])[0])

        # Send data words
        for i in range(0, len(data), 4):
            word = struct.unpack('<I', data[i:i+4])[0]
            self.write_word(word)

    def receive_response(self):
        """Receive a response packet from the device."""
        print("\n<<< Waiting for response...")

        # Read header: reserved(2) + status(2) + data_count(4)
        word0 = self.read_word()
        word1 = self.read_word()

        header = struct.pack('<II', word0, word1)
        reserved, status, data_count = struct.unpack('<HHI', header)

        status_name = STATUS_NAMES.get(status, f"UNKNOWN(0x{status:04x})")
        print(f"    Status: {status_name}, Data words: {data_count}")

        # Read data words
        data = b''
        for i in range(data_count):
            word = self.read_word()
            data += struct.pack('<I', word)

        return status, data


# ============================================================================
# Certificate and Token Generation
# ============================================================================

def load_private_key(key_path):
    """Load an Ed25519 private key from PEM file."""
    with open(key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError("Key must be Ed25519")
    return private_key


def get_public_key_bytes(private_key):
    """Get raw public key bytes from private key."""
    return private_key.public_key().public_bytes_raw()


def create_certificate(private_key):
    """Create a self-signed ADAC certificate.

    Args:
        private_key: Ed25519 private key

    Note: The device determines key generation by matching the certificate's
    public key against its provisioned ROTPKs, so oem_constraint is unused.
    """
    public_key = get_public_key_bytes(private_key)

    # Build certificate header (48 bytes)
    header = struct.pack(
        '<BB B B B B 2x H H I I 16s 16s',
        ADAC_MAJOR_VERSION,        # format_version.major
        ADAC_MINOR_VERSION,        # format_version.minor
        CRYPTOSYSTEM_ID_ED_25519_SHA512,  # signature_type
        CRYPTOSYSTEM_ID_ED_25519_SHA512,  # key_type
        ADAC_ROLE_ROOT,            # role
        ADAC_USAGE_NEUTRAL,        # usage
        PSA_LIFECYCLE_UNKNOWN,     # lifecycle
        0,                         # oem_constraint - unused (generation derived from key match)
        0,                         # extensions_bytes
        0,                         # soc_class
        b'\x00' * 16,              # soc_id
        b'\xFF' * 16               # permissions_mask (all permissions)
    )

    # Extensions hash (empty extensions = zero hash)
    extensions_hash = b'\x00' * EDDSA_ED25519_HASH_SIZE

    # Data to sign: header + public_key + extensions_hash
    tbs = header + public_key + extensions_hash

    # Sign with pure Ed25519
    signature = private_key.sign(tbs)

    assert len(signature) == EDDSA_ED25519_SIGNATURE_SIZE

    # Complete certificate: header + public_key + extensions_hash + signature
    certificate = header + public_key + extensions_hash + signature

    return certificate


def create_token(private_key, challenge_vector):
    """Create an authentication token signed with the private key."""
    # Token header
    header = struct.pack(
        '<BB B x I 16s',
        ADAC_MAJOR_VERSION,        # format_version.major
        ADAC_MINOR_VERSION,        # format_version.minor
        CRYPTOSYSTEM_ID_ED_25519_SHA512,  # signature_type
        0,                         # extensions_bytes
        b'\xFF' * 16               # requested_permissions (all)
    )

    # Extensions hash (empty)
    extensions_hash = b'\x00' * EDDSA_ED25519_HASH_SIZE

    # Data to sign: header + extensions_hash + challenge_vector
    tbs = header + extensions_hash + challenge_vector

    # Sign with pure Ed25519
    signature = private_key.sign(tbs)

    # Complete token: header + extensions_hash + signature
    token = header + extensions_hash + signature

    return token


def wrap_tlv(type_id, data):
    """Wrap data in a TLV structure."""
    # TLV: reserved(2) + type_id(2) + length(4) + value
    return struct.pack('<HHI', 0, type_id, len(data)) + data


# ============================================================================
# ADAC Authentication Flow
# ============================================================================

def perform_discovery(mailbox):
    """Send discovery command and get device capabilities."""
    print("\n" + "="*60)
    print("STEP 1: Discovery")
    print("="*60)

    mailbox.send_request(ADAC_DISCOVERY_CMD)
    status, data = mailbox.receive_response()

    if status == ADAC_SUCCESS:
        print(f"    Discovery data ({len(data)} bytes): {data.hex()}")
    return status, data


def perform_auth_start(mailbox):
    """Start authentication and get challenge vector."""
    print("\n" + "="*60)
    print("STEP 2: Auth Start")
    print("="*60)

    mailbox.send_request(ADAC_AUTH_START_CMD)
    status, data = mailbox.receive_response()

    if status == ADAC_SUCCESS and len(data) >= 36:
        # Challenge format: version(2) + reserved(2) + challenge_vector(32)
        version_major, version_minor, reserved = struct.unpack('<BBH', data[0:4])
        challenge_vector = data[4:36]
        print(f"    ADAC Version: {version_major}.{version_minor}")
        print(f"    Challenge Vector: {challenge_vector.hex()}")
        return status, challenge_vector

    return status, None


def perform_auth_response(mailbox, certificate, token):
    """Send certificate chain and token for authentication."""
    # Step 3a: Send certificate
    print("\n" + "="*60)
    print("STEP 3a: Send Certificate")
    print("="*60)

    cert_tlv = wrap_tlv(PSA_BINARY_CRT, certificate)
    print(f"    Certificate size: {len(certificate)} bytes")

    mailbox.send_request(ADAC_AUTH_RESPONSE_CMD, cert_tlv)
    status, _ = mailbox.receive_response()

    if status == ADAC_NEED_MORE_DATA:
        print("    Device accepted certificate, needs token...")
    elif status != ADAC_SUCCESS:
        print(f"    Certificate rejected with status: {STATUS_NAMES.get(status, status)}")
        return status, None

    # Step 3b: Send token
    print("\n" + "="*60)
    print("STEP 3b: Send Token")
    print("="*60)

    token_tlv = wrap_tlv(PSA_BINARY_TOKEN, token)
    print(f"    Token size: {len(token)} bytes")

    mailbox.send_request(ADAC_AUTH_RESPONSE_CMD, token_tlv)
    status, response_data = mailbox.receive_response()

    return status, response_data


def authenticate(key_path, serial_number=None, verbose=False, extra_verbose=False, skip_discovery=False, quick=False):
    """Perform full ADAC authentication.

    Args:
        key_path: Path to Ed25519 private key PEM file
        serial_number: J-Link probe serial number (optional)
        verbose: Enable verbose output
        extra_verbose: Enable extra verbose output (polling)
        skip_discovery: Skip the discovery step
        quick: Quick debug mode

    Note: Key generation is determined by the device based on which ROTPK
    matches the certificate's public key. No need to specify it here.
    """
    print("\n" + "#"*60)
    print("# ADAC Authentication")
    print("#"*60)

    # Load private key
    print(f"\nLoading private key from: {key_path}")
    private_key = load_private_key(key_path)
    public_key = get_public_key_bytes(private_key)
    print(f"Public key: {public_key.hex()}")

    # Step 0: Enter ADAC mode using minimal J-Link (same as test script)
    print("\n[Entering ADAC mode]")

    # Minimal J-Link setup (exactly like test_adac_reset.py CtrlApAccess)
    print("  Connecting via J-Link...")
    jlink = pylink.JLink()
    jlink.open(serial_no=serial_number)
    jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
    jlink.set_speed(4000)
    try:
        jlink.connect('CORTEX-M33', verbose=False)
    except pylink.errors.JLinkException:
        pass  # May fail on protected devices
    jlink.coresight_configure()

    ap_num = CTRL_AP_INDEX
    DP_SELECT = 0x08

    def write_ap_reg(reg_offset, value):
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (ap_num << 24) | (ap_bank << 4)
        jlink.coresight_write(DP_SELECT >> 2, select_val, ap=False)
        reg_in_bank = reg_offset & 0x0F
        jlink.coresight_write(reg_in_bank >> 2, value, ap=True)

    def read_ap_reg(reg_offset):
        ap_bank = (reg_offset >> 4) & 0xF
        select_val = (ap_num << 24) | (ap_bank << 4)
        jlink.coresight_write(DP_SELECT >> 2, select_val, ap=False)
        reg_in_bank = reg_offset & 0x0F
        return jlink.coresight_read(reg_in_bank >> 2, ap=True)

    # Quick debug mode: minimal interaction to avoid spurious resets
    if quick:
        print("  [Quick mode] Triggering hard reset...")
        write_ap_reg(CTRLAP_RESET, CTRLAP_RESET_HARD)

        print("  [Quick mode] Waiting 100ms for reset to take effect...")
        time.sleep(0.1)

        print("  [Quick mode] Clearing reset register...")
        write_ap_reg(CTRLAP_RESET, CTRLAP_RESET_NONE)

        print("  [Quick mode] Disconnecting J-Link before sending trigger...")
        jlink.close()

        print("  [Quick mode] Waiting 2s for device to boot and reach ADAC check...")
        time.sleep(2.0)

        # Reconnect briefly just to send the trigger
        print("  [Quick mode] Reconnecting to send trigger...")
        jlink = pylink.JLink()
        jlink.open(serial_no=serial_number)
        jlink.set_tif(pylink.enums.JLinkInterfaces.SWD)
        jlink.set_speed(4000)
        try:
            jlink.connect('CORTEX-M33', verbose=False)
        except pylink.errors.JLinkException:
            pass
        jlink.coresight_configure()

        print("  [Quick mode] Writing trigger word 0xADAC0001...")
        write_ap_reg(CTRLAP_MAILBOX_TXDATA, 0xADAC0001)

        print("  [Quick mode] Disconnecting immediately...")
        jlink.close()

        print("  [Quick mode] Done. Check device logs.")
        return True

    # Normal mode: Keep connection open, minimal register access
    print("  Triggering CTRL-AP hard reset...")
    write_ap_reg(CTRLAP_RESET, CTRLAP_RESET_HARD)

    print("  Waiting 100ms for reset to take effect...")
    time.sleep(0.1)

    print("  Clearing reset register...")
    write_ap_reg(CTRLAP_RESET, CTRLAP_RESET_NONE)

    # Device boots and checks DBGPWRUPREQ - if debugger is connected it waits for trigger
    # Give device time to boot (~200ms) before we send the trigger
    print("  Waiting 300ms for device to boot...")
    time.sleep(0.3)

    print("  Writing trigger word 0xADAC0001...")
    write_ap_reg(CTRLAP_MAILBOX_TXDATA, 0xADAC0001)

    # Wait for device to read trigger and initialize ADAC
    print("  Waiting 500ms for device to process trigger...")
    time.sleep(0.5)

    print("\n[Starting ADAC protocol]")

    mailbox = CtrlApMailbox.__new__(CtrlApMailbox)
    mailbox.jlink = jlink
    mailbox.ctrl_ap_num = ap_num
    mailbox.verbose = verbose
    mailbox.extra_verbose = extra_verbose
    mailbox.target_connected = False
    mailbox.DP_SELECT = DP_SELECT

    try:

        # Step 1: Discovery (optional)
        if not skip_discovery:
            status, _ = perform_discovery(mailbox)
            if status != ADAC_SUCCESS:
                print(f"\n*** Discovery failed with status: {STATUS_NAMES.get(status, status)}")
                return False

        # Step 2: Auth Start - get challenge
        status, challenge_vector = perform_auth_start(mailbox)
        if status != ADAC_SUCCESS or challenge_vector is None:
            print(f"\n*** Auth Start failed with status: {STATUS_NAMES.get(status, status)}")
            return False

        # Generate certificate and token
        print("\nGenerating certificate...")
        certificate = create_certificate(private_key)
        print(f"    Certificate ({len(certificate)} bytes): {certificate[:32].hex()}...")

        print("\nGenerating token with challenge signature...")
        token = create_token(private_key, challenge_vector)
        print(f"    Token ({len(token)} bytes): {token[:32].hex()}...")

        # Step 3: Auth Response
        status, _ = perform_auth_response(mailbox, certificate, token)

        if status == ADAC_SUCCESS:
            print("\n" + "="*60)
            print("*** AUTHENTICATION SUCCESSFUL ***")
            print("Debug access has been unlocked!")
            print("="*60)

            # Step 4: Close session to properly end the ADAC loop on device
            print("\n[Closing ADAC session]")
            try:
                mailbox.send_request(ADAC_CLOSE_SESSION_CMD)
                close_status, _ = mailbox.receive_response()
                if close_status == ADAC_SUCCESS:
                    print("  Session closed successfully")
                else:
                    print(f"  Warning: Close returned status {close_status}")
            except Exception as e:
                print(f"  Warning: Could not close session: {e}")

            return True
        else:
            print(f"\n*** Authentication failed with status: {STATUS_NAMES.get(status, status)}")
            return False

    finally:
        mailbox.close()


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ADAC Host Script - Authenticate debug access on nRF54L15",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Authenticate with any provisioned key
    python3 adac_host.py --key output/private-key.pem
    python3 adac_host.py --key output/private-key-gen1.pem
    python3 adac_host.py --key output/private-key-gen2.pem

    # With specific probe unique ID
    python3 adac_host.py --key output/private-key.pem --probe 123456789

    # Verbose output
    python3 adac_host.py --key output/private-key.pem -v

Key Generations:
    The device determines the key generation by matching the certificate's
    public key against its provisioned ROTPKs. When authenticated with
    generation N, the device will automatically revoke all generations < N
    (if auto-revoke is enabled).
"""
    )

    parser.add_argument(
        '--key', '-k',
        required=True,
        help='Path to Ed25519 private key (PEM format)'
    )
    parser.add_argument(
        '--probe', '-p',
        help='Debug probe unique ID (optional)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='count',
        default=0,
        help='Enable verbose output (-v for verbose, -vv for extra verbose with polling)'
    )
    parser.add_argument(
        '--skip-discovery',
        action='store_true',
        help='Skip discovery step'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick debug mode: send trigger, wait briefly, then exit (for debugging device crashes)'
    )

    args = parser.parse_args()

    if not os.path.exists(args.key):
        print(f"Error: Key file not found: {args.key}")
        return 1

    try:
        success = authenticate(
            args.key,
            serial_number=int(args.probe) if args.probe else None,
            verbose=args.verbose >= 1,
            extra_verbose=args.verbose >= 2,
            skip_discovery=args.skip_discovery,
            quick=args.quick
        )
        return 0 if success else 1
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose >= 1:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
