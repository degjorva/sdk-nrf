#!/usr/bin/env python3
#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

"""
nrfutil-kms Subprocess Backend for ADAC

This script implements the nrfutil-kms subprocess protocol for ADAC key management.
It listens on stdin for JSON messages and responds on stdout with JSON messages.

Usage:
    # Register as a subprocess backend
    nrfutil kms service add subprocess adac_local \
      --key-template "{key_name}" \
      --command python3 /path/to/adac_kms_backend.py /path/to/keys

    # Test the backend
    nrfutil kms service test adac_local gen0

    # Use with nrfutil-device
    nrfutil device x-adac-lcs-change --serial-number XXX --kms adac_local

For more information, see the ADAC sample documentation.
"""

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Ed25519ph requires OpenSSL 3.x for proper RFC 8032 implementation.
# The dom2 prefix must be inserted at specific positions in internal hash
# computations, which NaCl doesn't support.


# Key name to filename mapping
KEY_NAME_MAP = {
    "gen0": ("private-key.pem", "public-key.pem"),
    "gen1": ("private-key-gen1.pem", "public-key-gen1.pem"),
    "gen2": ("private-key-gen2.pem", "public-key-gen2.pem"),
    "gen3": ("private-key-gen3.pem", "public-key-gen3.pem"),
}


class ErrorResponse:
    """Error response message."""

    def __init__(self, message: str):
        self.message = message

    def to_json(self) -> dict:
        return {"type": "error", "version": "1", "reason": self.message}


class PublicKeyResponse:
    """Public key response message."""

    def __init__(self, key_type: str, base_64_bytes: str):
        self.key_type = key_type
        self.base_64_bytes = base_64_bytes

    def to_json(self) -> dict:
        return {
            "type": "public-key",
            "version": "1",
            "keyType": self.key_type,
            "base64Bytes": self.base_64_bytes,
        }


class SignResponse:
    """Sign response message."""

    def __init__(self, base_64_bytes: str):
        self.base_64_bytes = base_64_bytes

    def to_json(self) -> dict:
        return {
            "type": "sign",
            "version": "1",
            "base64Bytes": self.base_64_bytes,
        }


CUSTOM_TYPES = [ErrorResponse, PublicKeyResponse, SignResponse]


class CustomEncoder(json.JSONEncoder):
    """Custom JSON encoder for response types."""

    def default(self, obj):
        if any(isinstance(obj, Type) for Type in CUSTOM_TYPES):
            return obj.to_json()
        return super().default(obj)


def respond(response) -> None:
    """Send a JSON response to stdout."""
    print(json.dumps(response, cls=CustomEncoder), flush=True)


def get_key_files(key_name: str) -> tuple[str, str]:
    """Get the private and public key filenames for a key name.

    Args:
        key_name: Key name (e.g., "gen0", "gen1", etc.)

    Returns:
        Tuple of (private_key_filename, public_key_filename)

    Raises:
        ValueError: If key name is not recognized
    """
    if key_name in KEY_NAME_MAP:
        return KEY_NAME_MAP[key_name]

    # Also support direct generation numbers
    if key_name.isdigit():
        gen = int(key_name)
        if 0 <= gen <= 3:
            suffix = f"-gen{gen}" if gen > 0 else ""
            return (f"private-key{suffix}.pem", f"public-key{suffix}.pem")

    raise ValueError(f"Unknown key name: {key_name}")


def load_public_key(key_dir: Path, key_name: str) -> bytes:
    """Load a public key and return raw bytes.

    Args:
        key_dir: Directory containing key files
        key_name: Key name to load

    Returns:
        Raw public key bytes (32 bytes for Ed25519)
    """
    _, public_key_file = get_key_files(key_name)
    public_key_path = key_dir / public_key_file

    with open(public_key_path, "rb") as f:
        key_data = f.read()

    public_key = serialization.load_pem_public_key(key_data)

    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise ValueError(f"Key {key_name} is not an Ed25519 key")

    return public_key.public_bytes_raw()


def load_private_key(key_dir: Path, key_name: str) -> ed25519.Ed25519PrivateKey:
    """Load a private key.

    Args:
        key_dir: Directory containing key files
        key_name: Key name to load

    Returns:
        Ed25519 private key
    """
    private_key_file, _ = get_key_files(key_name)
    private_key_path = key_dir / private_key_file

    with open(private_key_path, "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(key_data, password=None)

    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise ValueError(f"Key {key_name} is not an Ed25519 key")

    return private_key


def _get_openssl_cmd():
    """Get the OpenSSL command and library path for Ed25519ph support.

    Ed25519ph requires OpenSSL 3.2+ with the correct syntax:
        openssl pkeyutl -sign -inkey key.pem -rawin -in msg -pkeyopt instance:Ed25519ph

    Returns tuple of (openssl_path, env_dict) where env_dict contains LD_LIBRARY_PATH if needed.
    """
    import subprocess
    import os

    openssl_cmd = os.environ.get('OPENSSL_PATH', 'openssl')
    openssl_lib = os.environ.get('OPENSSL_LIB_PATH', '')

    # Common locations for OpenSSL 3.2+ installations
    alt_locations = [
        ('/tmp/openssl-3.3.2/apps/openssl', '/tmp/openssl-3.3.2'),  # Built from source
        ('/opt/openssl33/bin/openssl', '/opt/openssl33/lib'),
        ('/opt/openssl32/bin/openssl', '/opt/openssl32/lib'),
        ('/usr/local/bin/openssl', '/usr/local/lib'),
        ('/opt/homebrew/bin/openssl', '/opt/homebrew/lib'),
    ]

    def check_openssl(cmd, lib_path=''):
        """Check if OpenSSL supports Ed25519ph (needs 3.2+)."""
        env = os.environ.copy()
        if lib_path:
            env['LD_LIBRARY_PATH'] = lib_path + ':' + env.get('LD_LIBRARY_PATH', '')
        try:
            result = subprocess.run([cmd, 'version'], capture_output=True, text=True, env=env)
            version = result.stdout.strip()
            if 'OpenSSL 3.' in version:
                parts = version.split()
                if len(parts) >= 2:
                    ver = parts[1].split('.')
                    if len(ver) >= 2 and int(ver[1]) >= 2:
                        return True, version, env
            return False, version, env
        except (FileNotFoundError, Exception):
            return False, None, env

    # Check custom path first
    if os.path.exists(openssl_cmd):
        ok, ver, env = check_openssl(openssl_cmd, openssl_lib)
        if ok:
            return openssl_cmd, env

    # Try alternative locations
    for cmd, lib in alt_locations:
        if os.path.exists(cmd):
            ok, ver, env = check_openssl(cmd, lib)
            if ok:
                return cmd, env

    # Check system openssl
    ok, ver, env = check_openssl('openssl')
    if ok:
        return 'openssl', env

    raise RuntimeError(
        f"OpenSSL 3.2+ required for Ed25519ph signing.\n"
        f"Found: {ver or 'none'}\n"
        f"Options:\n"
        f"  1. Build OpenSSL 3.3: cd /tmp && wget https://www.openssl.org/source/openssl-3.3.2.tar.gz && tar xzf openssl-3.3.2.tar.gz && cd openssl-3.3.2 && ./Configure && make\n"
        f"  2. Set OPENSSL_PATH=/path/to/openssl and OPENSSL_LIB_PATH=/path/to/lib"
    )


def sign_with_key(key_dir: Path, key_name: str, data: bytes) -> bytes:
    """Sign data with Ed25519ph (prehashed Ed25519).

    Uses OpenSSL 3.2+ for proper RFC 8032 Ed25519ph signing.
    Set OPENSSL_PATH and OPENSSL_LIB_PATH environment variables if not in PATH.

    Args:
        key_dir: Directory containing key files
        key_name: Key name to use for signing
        data: Data to sign

    Returns:
        Signature bytes (64 bytes for Ed25519ph)
    """
    import subprocess
    import tempfile
    import os

    openssl_cmd, openssl_env = _get_openssl_cmd()
    private_key = load_private_key(key_dir, key_name)

    # Write private key as PEM
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as key_file:
        key_file.write(pem_data)
        key_path = key_file.name

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as msg_file:
        msg_file.write(data)
        msg_path = msg_file.name

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.sig', delete=False) as sig_file:
        sig_path = sig_file.name

    try:
        # OpenSSL 3.2+ Ed25519ph signing with -pkeyopt instance:Ed25519ph
        cmd = [
            openssl_cmd, 'pkeyutl',
            '-sign',
            '-inkey', key_path,
            '-rawin',
            '-in', msg_path,
            '-out', sig_path,
            '-pkeyopt', 'instance:Ed25519ph'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, env=openssl_env)
        if result.returncode != 0:
            raise RuntimeError(f"OpenSSL Ed25519ph signing failed: {result.stderr}")

        with open(sig_path, 'rb') as f:
            signature = f.read()

        if len(signature) != 64:
            raise RuntimeError(f"Unexpected signature length: {len(signature)}")

        return signature

    finally:
        for path in [key_path, msg_path, sig_path]:
            try:
                os.unlink(path)
            except:
                pass


def main(args: list[str]) -> int:
    """Main entry point.

    Args:
        args: Command-line arguments (first arg is key directory path)

    Returns:
        Exit code (0 for success)
    """
    # Get key directory from arguments
    if args:
        key_dir = Path(args[0])
    else:
        key_dir = Path("output")

    if not key_dir.exists():
        # Write error to stderr (not part of protocol)
        print(f"Warning: Key directory does not exist: {key_dir}", file=sys.stderr)

    # Process JSON messages from stdin
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as e:
            respond(ErrorResponse(f"Unable to parse request as JSON: {e}"))
            continue

        if "type" not in data:
            respond(ErrorResponse("Request JSON has no 'type' field"))
            continue

        msg_type = data["type"]

        if msg_type == "finish":
            return 0

        elif msg_type == "public-key":
            version = data.get("version", "1")
            if version != "1":
                respond(ErrorResponse(f"Unknown version of public-key request: {version}"))
                continue

            key_name = data.get("keyName") or data.get("key_name")
            if not key_name:
                respond(ErrorResponse("public-key request missing 'keyName' field"))
                continue

            try:
                public_key_bytes = load_public_key(key_dir, key_name)
                base64_bytes = base64.b64encode(public_key_bytes).decode("utf-8")
                respond(PublicKeyResponse("ed25519", base64_bytes))
            except FileNotFoundError:
                respond(ErrorResponse(f"Key not found: {key_name} in {key_dir}"))
            except ValueError as e:
                respond(ErrorResponse(str(e)))
            except Exception as e:
                respond(ErrorResponse(f"Failed to load public key: {e}"))

        elif msg_type == "sign":
            version = data.get("version", "1")
            if version != "1":
                respond(ErrorResponse(f"Unknown version of sign request: {version}"))
                continue

            key_name = data.get("keyName") or data.get("key_name")
            if not key_name:
                respond(ErrorResponse("sign request missing 'keyName' field"))
                continue

            base64_data = data.get("base64Bytes") or data.get("base_64_bytes")
            if not base64_data:
                respond(ErrorResponse("sign request missing 'base64Bytes' field"))
                continue

            try:
                data_bytes = base64.b64decode(base64_data)
                signature = sign_with_key(key_dir, key_name, data_bytes)
                base64_sig = base64.b64encode(signature).decode("utf-8")
                respond(SignResponse(base64_sig))
            except FileNotFoundError:
                respond(ErrorResponse(f"Key not found: {key_name} in {key_dir}"))
            except ValueError as e:
                respond(ErrorResponse(str(e)))
            except Exception as e:
                respond(ErrorResponse(f"Failed to sign: {e}"))

        else:
            respond(ErrorResponse(f"Unrecognised request type: {msg_type}"))

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
