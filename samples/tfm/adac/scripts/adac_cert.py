#!/usr/bin/env python3
"""
ADAC Certificate Generator for nRF54L15

Generates Ed25519 keys and ADAC certificates for testing.
Uses Ed25519ph (prehashed) signing as per ADAC specification.

Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
"""

import argparse
import hashlib
import struct
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Ed25519ph requires OpenSSL 3.x for proper RFC 8032 implementation.
# The dom2 prefix must be inserted at specific positions in internal hash
# computations, which NaCl doesn't support.

ADAC_MAJOR_VERSION = 1
ADAC_MINOR_VERSION = 0

EDDSA_ED25519_PUBLIC_KEY_SIZE = 32
EDDSA_ED25519_SIGNATURE_SIZE = 64
EDDSA_ED25519_HASH_SIZE = 64

CRYPTOSYSTEM_ID_ED_25519_SHA512 = 0x05 #Ed25519 EdDSA with SHA-512

ADAC_ROLE_ROOT = 0x1 # The certificate is a root certificate
ADAC_ROLE_INTERMEDIATE = 0x2 # The certificate is intermediate
ADAC_ROLE_LEAF = 0x3 # The certificate is a leaf certificate

ADAC_USAGE_NEUTRAL = 0x0 # The certificate has no special usage.
ADAC_USAGE_INTERMEDIATE = 0x1 # The certificate is only for authentication.
ADAC_USAGE_RMA = 0x2 # The certificate moves the device to the RMA lifecycle state

PSA_LIFECYCLE_UNKNOWN = 0x0000 # The lifecycle state is unknown.

class PrivateKey:
    def __init__(self):
        """Generate private key."""
        self.private_key = ed25519.Ed25519PrivateKey.generate()

    def pem(self):
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return private_pem

    def raw(self):
        private_key_bytes = self.private_key.private_bytes_raw()
        assert EDDSA_ED25519_PUBLIC_KEY_SIZE == len(private_key_bytes)

        return private_key_bytes

class PublicKey:
    def __init__(self, public_key):
        """Generate public key from private key."""
        self.public_key = public_key
    def pem(self):
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_pem

    def raw(self):
        return self.public_key.public_bytes_raw()

class AdacVersion:
    def __init__(self, major, minor):
        self.major = major
        self.minor = minor

    def pack(self):
        return struct.pack('BB', self.major, self.minor)

class AdacCertificateHeaderV1_0:
    def __init__(self, format_version, signature_type, key_type, role, usage, lifecycle, oem_constraint, extensions_bytes, soc_class, soc_id, permissions_mask):
        self.format_version = format_version
        self.signature_type = signature_type
        self.key_type = key_type
        self.role = role
        self.usage = usage
        self._reserved = (0, 0)
        self.lifecycle = lifecycle
        self.oem_constraint = oem_constraint
        self.extensions_bytes = extensions_bytes
        self.soc_class = soc_class
        self.soc_id = soc_id
        self.permissions_mask = permissions_mask

    def pack(self):
        return struct.pack(
            'BB B B B B 2x H H I I 16s 16s',
            self.format_version.major,
            self.format_version.minor,
            self.signature_type,
            self.key_type,
            self.role,
            self.usage,
            self.lifecycle,
            self.oem_constraint,
            self.extensions_bytes,
            self.soc_class,
            self.soc_id,
            self.permissions_mask
        )

class Extensions:
    def __init__(self, extensions):
        self.extensions = extensions

    def pack(self):
        return struct.pack(f'{len(self.extensions)}I', *self.extensions)

    def length(self):
        return 0 #len(self.extensions)

    def hash(self):
        hash = b'\x00' * EDDSA_ED25519_HASH_SIZE
        assert len(hash) == EDDSA_ED25519_HASH_SIZE

        return hash

    def raw(self):
        return []

def _get_openssl_cmd():
    """Get the OpenSSL command and library path for Ed25519ph support.

    Ed25519ph requires OpenSSL 3.2+ with the correct syntax:
        openssl pkeyutl -sign -inkey key.pem -rawin -in msg -pkeyopt instance:Ed25519ph

    Returns tuple of (openssl_path, env_dict) where env_dict contains LD_LIBRARY_PATH if needed.
    """
    import subprocess

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


def ed25519ph_sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message using Ed25519ph (prehashed Ed25519).

    Uses OpenSSL 3.2+ for proper RFC 8032 Ed25519ph signing.
    Set OPENSSL_PATH and OPENSSL_LIB_PATH environment variables if not in PATH.

    Args:
        seed: 32-byte Ed25519 private key seed
        message: Message to sign

    Returns:
        64-byte Ed25519ph signature
    """
    import subprocess
    import tempfile

    openssl_cmd, openssl_env = _get_openssl_cmd()

    # Create Ed25519 private key from seed and write as PEM
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as key_file:
        key_file.write(pem_data)
        key_path = key_file.name

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as msg_file:
        msg_file.write(message)
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

        assert len(signature) == EDDSA_ED25519_SIGNATURE_SIZE
        return signature

    finally:
        for path in [key_path, msg_path, sig_path]:
            try:
                os.unlink(path)
            except:
                pass


class CertificateEd255Ed255:
    def __init__(self, header, pubkey, extensions_hash, extensions):
        self.header = header
        self.pubkey = pubkey
        self.extensions_hash = extensions_hash
        self.extensions = extensions

    def sign(self, private_key_seed):
        """Sign the certificate with Ed25519ph (prehashed)."""
        tbs = self.header.pack() + self.pubkey + self.extensions_hash
        self.signature = ed25519ph_sign(private_key_seed, tbs)
        assert len(self.signature) == EDDSA_ED25519_SIGNATURE_SIZE

    def pack(self):
        # Pack the header separately if it's a complex structure
        header_packed = self.header.pack()

        # Pack the main structure
        main_packed = struct.pack(
            f'{len(self.pubkey)}s {len(self.extensions_hash)}s {len(self.signature)}s',
            self.pubkey,
            self.extensions_hash,
            self.signature
        )

        # Pack the extensions
        extensions_packed = struct.pack(f'{len(self.extensions)}I', *self.extensions)

        return header_packed + main_packed + extensions_packed

    def verify(self, public_key):
        # Verify the signature
        public_key.verify(self.signature, self.header.pack() + self.pubkey + self.extensions_hash)

def generate_certificate(output_dir, generation=0):
    """
    Function to generate ADAC certificates and keys.

    Args:
        output_dir (str): Directory to save the generated certificate.
        generation (int): Key generation index (0-3) stored in oem_constraint field.
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    print(f"Generating certificates and keys in {output_dir}")
    print(f"Key generation: {generation}")

    # Paths for the key files (include generation in filename if not 0)
    suffix = f"-gen{generation}" if generation > 0 else ""
    private_key_path = os.path.join(output_dir, f'private-key{suffix}.pem')
    public_key_path = os.path.join(output_dir, f'public-key{suffix}.pem')

    # Generate keys.
    private_key = PrivateKey()
    with open(private_key_path, 'wb') as f:
            f.write(private_key.pem())
    print("Private key:\r\n" + private_key.pem().decode('utf-8'))

    public_key = PublicKey(private_key.private_key.public_key())
    with open(public_key_path, 'wb') as f:
            f.write(public_key.pem())

    print("Public key:\r\n" + public_key.pem().decode('utf-8'))
    hex_string = ', '.join(f'0x{byte:02x}' for byte in public_key.raw())
    print(f"Public key bytes (for generation {generation}):")
    print(hex_string)
    print("\r\n")

    # Calculate KMU slot for this generation (base slot 207, 2 slots per key)
    kmu_slot = 207 + (generation * 2)
    print(f"KMU slots for generation {generation}: {kmu_slot}-{kmu_slot+1}")
    print("")

    extensions = Extensions([0])

    version = AdacVersion(ADAC_MAJOR_VERSION, ADAC_MINOR_VERSION)
    header = AdacCertificateHeaderV1_0(
        version,
        CRYPTOSYSTEM_ID_ED_25519_SHA512, # signature_type
        CRYPTOSYSTEM_ID_ED_25519_SHA512, # key_type
        ADAC_ROLE_ROOT, # role
        ADAC_USAGE_NEUTRAL, # usage
        PSA_LIFECYCLE_UNKNOWN, # lifecycle
        generation, # oem_constraint - stores key generation
        extensions.length(), # extensions_bytes
        0, # soc_class
        b'\x00'*16, # soc_id
        b'\xFF'*16 # permissions_mask
    )

    certificate = CertificateEd255Ed255(
        header,
        public_key.raw(),
        extensions.hash(),
        extensions.raw()
    )

    # Sign the certificate with Ed25519ph (prehashed)
    certificate.sign(private_key.raw())

    packed_data = certificate.pack()
    print("Certificate length: ", len(packed_data))
    print(packed_data)
    print("hex:")
    hex_string = ', '.join(f'0x{byte:02x}' for byte in packed_data)
    print(hex_string)

def main():
    parser = argparse.ArgumentParser(
        description="Generate ADAC certificates and keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate key for generation 0 (default)
    python3 adac_cert.py output/

    # Generate key for generation 2
    python3 adac_cert.py output/ --generation 2

    # Generate all 4 generations
    for i in 0 1 2 3; do python3 adac_cert.py output/ -g $i; done

Key Generations:
    Generation 0: KMU slots 207-208
    Generation 1: KMU slots 209-210
    Generation 2: KMU slots 211-212
    Generation 3: KMU slots 213-214

The oem_constraint field in the certificate stores the generation index.
Authenticating with a newer generation will revoke older generations.
"""
    )
    parser.add_argument("output_dir", type=str,
                        help="Directory to save the generated certificates and keys")
    parser.add_argument("--generation", "-g", type=int, default=0, choices=[0, 1, 2, 3],
                        help="Key generation index (0-3, default: 0)")

    args = parser.parse_args()

    generate_certificate(args.output_dir, args.generation)

if __name__ == "__main__":
    main()
