#!/usr/bin/env python3
"""
ADAC Key Provisioning Script for nRF54L15

Generates Ed25519 keys for all 4 ADAC key generations and creates a JSON file
compatible with nrfutil for KMU provisioning.

Usage:
    # Generate keys and create provisioning JSON
    python3 adac_provision.py --output output/

    # Generate keys and provision to device
    python3 adac_provision.py --output output/ --provision

    # Provision existing keys (keys already generated)
    python3 adac_provision.py --output output/ --provision --skip-keygen

    # Generate only specific generations
    python3 adac_provision.py --output output/ --generations 0 2 3

Copyright (c) 2025 Nordic Semiconductor ASA
SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# KMU slot configuration (must match tfm_adac.c)
KMU_SLOT_BASE = 207
SLOTS_PER_KEY = 2  # Each 32-byte Ed25519 key uses 2 x 16-byte slots
MAX_GENERATIONS = 4

# Path to generate_psa_key_attributes.py (relative to nrf repo)
GENERATE_PSA_KEY_SCRIPT = "scripts/generate_psa_key_attributes.py"


def get_kmu_slot(generation: int) -> int:
    """Calculate the KMU slot for a given generation."""
    return KMU_SLOT_BASE + (generation * SLOTS_PER_KEY)


def generate_key_pair(output_dir: Path, generation: int) -> tuple[Path, Path]:
    """Generate an Ed25519 key pair for a given generation.

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    suffix = f"-gen{generation}" if generation > 0 else ""
    private_key_path = output_dir / f"private-key{suffix}.pem"
    public_key_path = output_dir / f"public-key{suffix}.pem"

    # Generate new key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Write private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, 'wb') as f:
        f.write(private_pem)

    # Write public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, 'wb') as f:
        f.write(public_pem)

    return private_key_path, public_key_path


def load_public_key(key_path: Path) -> bytes:
    """Load a public key from PEM file and return raw bytes."""
    with open(key_path, 'rb') as f:
        key_data = f.read()

    try:
        public_key = serialization.load_pem_public_key(key_data)
    except ValueError:
        # Try loading as private key
        private_key = serialization.load_pem_private_key(key_data, password=None)
        public_key = private_key.public_key()

    return public_key.public_bytes_raw()


def create_key_metadata(slot_id: int) -> str:
    """Create PSA key metadata for an Ed25519ph public key.

    This replicates the metadata generation from generate_psa_key_attributes.py
    for an Ed25519ph public key with VERIFY and EXPORT usage.

    Note: EXPORT is required because tfm_adac.c uses psa_export_key() to read
    the public key from KMU for signature verification.
    """
    # PSA key attributes for Ed25519ph public key
    # Type: ECC_PUBLIC_KEY_TWISTED_EDWARDS (0x4142)
    # Usage: VERIFY | EXPORT (0x2801)
    #   - VERIFY = PSA_KEY_USAGE_VERIFY_MESSAGE (0x0800) | PSA_KEY_USAGE_VERIFY_HASH (0x2000)
    #   - EXPORT = PSA_KEY_USAGE_EXPORT (0x0001)
    # Algorithm: ED25519PH (0x0600090B)
    # Location: LOCATION_CRACEN_KMU (0x804E4B00)
    # Persistence: PERSISTENCE_DEFAULT (1)
    # CRACEN Usage: RAW (3)
    # Key bits: 255

    key_type = 0x4142  # ECC_PUBLIC_KEY_TWISTED_EDWARDS
    key_bits = 255
    location = 0x804E4B00  # LOCATION_CRACEN_KMU
    persistence = 1  # PERSISTENCE_DEFAULT
    key_lifetime = location | (persistence & 0xFF)
    usage = 0x2801  # PSA_KEY_USAGE_VERIFY | PSA_KEY_USAGE_EXPORT
    alg0 = 0x0600090B  # PSA_ALG_ED25519PH
    alg1 = 0  # NONE
    cracen_usage = 3  # RAW

    # PSA Key ID = 0x7FFF0000 | (cracen_usage << 12) | (slot_id & 0xFF)
    key_id = 0x7FFF0000 | (cracen_usage << 12) | (slot_id & 0xFF)

    # Build metadata struct (matches PlatformKeyAttributes.pack() from generate_psa_key_attributes.py)
    # struct format: <hhIIIIII (little-endian)
    # - key_type: 2 bytes (signed short)
    # - key_bits: 2 bytes (signed short)
    # - key_lifetime: 4 bytes
    # - usage: 4 bytes
    # - alg0: 4 bytes
    # - alg1: 4 bytes
    # - key_id: 4 bytes
    # - reserved: 4 bytes (always 0)
    metadata = struct.pack('<hhIIIIII', key_type, key_bits, key_lifetime, usage, alg0, alg1, key_id, 0)

    return f"0x{metadata.hex()}"


def create_provisioning_json(output_dir: Path, generations: list[int]) -> Path:
    """Create a JSON file for nrfutil KMU provisioning.

    Args:
        output_dir: Directory containing the key files
        generations: List of generation indices to include

    Returns:
        Path to the created JSON file
    """
    keyslots = []

    for gen in generations:
        suffix = f"-gen{gen}" if gen > 0 else ""
        public_key_path = output_dir / f"public-key{suffix}.pem"

        if not public_key_path.exists():
            print(f"Error: Public key not found: {public_key_path}")
            sys.exit(1)

        # Load public key bytes
        public_key_bytes = load_public_key(public_key_path)
        slot_id = get_kmu_slot(gen)

        # Create metadata
        metadata = create_key_metadata(slot_id)

        # Add to keyslots
        keyslots.append({
            "metadata": metadata,
            "value": f"0x{public_key_bytes.hex()}"
        })

        print(f"  Generation {gen}: slot {slot_id}, key {public_key_bytes.hex()[:16]}...")

    # Create JSON structure with version field required by nrfutil
    json_data = {
        "version": 0,
        "keyslots": keyslots
    }

    # Write JSON file
    json_path = output_dir / "adac_keys.json"
    with open(json_path, 'w') as f:
        json.dump(json_data, f, indent=4)

    return json_path


def provision_keys(json_path: Path, serial_number: str = None) -> bool:
    """Provision keys to device using nrfutil.

    Args:
        json_path: Path to the JSON key file
        serial_number: Optional J-Link serial number

    Returns:
        True if successful, False otherwise
    """
    cmd = ["nrfutil", "device", "x-provision-keys", "--key-file", str(json_path)]

    if serial_number:
        cmd.extend(["--serial-number", serial_number])

    print(f"\nRunning: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error provisioning keys: {e}")
        if e.stdout:
            print(f"stdout: {e.stdout}")
        if e.stderr:
            print(f"stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print("Error: nrfutil not found. Please install nRF Util:")
        print("  https://www.nordicsemi.com/Products/Development-tools/nRF-Util")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Generate and provision ADAC keys for nRF54L15",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate all 4 generations of keys
    python3 adac_provision.py --output output/

    # Generate keys and provision to device
    python3 adac_provision.py --output output/ --provision

    # Generate only specific generations
    python3 adac_provision.py --output output/ --generations 0 1

    # Provision existing keys (skip key generation)
    python3 adac_provision.py --output output/ --provision --skip-keygen

    # Provision to specific probe
    python3 adac_provision.py --output output/ --provision --probe 123456789

KMU Slot Layout:
    Generation 0: slots 207-208
    Generation 1: slots 209-210
    Generation 2: slots 211-212
    Generation 3: slots 213-214

After provisioning, use adac_host.py to authenticate:
    python3 adac_host.py --key output/private-key.pem --generation 0
"""
    )

    parser.add_argument(
        "--output", "-o",
        type=str,
        required=True,
        help="Output directory for keys and JSON file"
    )
    parser.add_argument(
        "--generations", "-g",
        type=int,
        nargs="+",
        default=[0, 1, 2, 3],
        choices=[0, 1, 2, 3],
        help="Key generations to generate (default: all 4)"
    )
    parser.add_argument(
        "--provision", "-p",
        action="store_true",
        help="Provision keys to device after generation"
    )
    parser.add_argument(
        "--skip-keygen",
        action="store_true",
        help="Skip key generation (use existing keys)"
    )
    parser.add_argument(
        "--probe",
        type=str,
        help="J-Link probe serial number (optional)"
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    generations = sorted(set(args.generations))

    print("=" * 60)
    print("ADAC Key Provisioning")
    print("=" * 60)
    print(f"Output directory: {output_dir}")
    print(f"Generations: {generations}")
    print(f"KMU slot base: {KMU_SLOT_BASE}")
    print()

    # Generate keys
    if not args.skip_keygen:
        print("Generating Ed25519 key pairs...")
        for gen in generations:
            private_path, public_path = generate_key_pair(output_dir, gen)
            slot = get_kmu_slot(gen)
            print(f"  Generation {gen}: {private_path.name}, {public_path.name} (KMU slot {slot})")
        print()

    # Create provisioning JSON
    print("Creating provisioning JSON...")
    json_path = create_provisioning_json(output_dir, generations)
    print(f"  Created: {json_path}")
    print()

    # Provision if requested
    if args.provision:
        print("Provisioning keys to device...")
        if provision_keys(json_path, args.probe):
            print("\nProvisioning successful!")
            print("\nNext steps:")
            print("  1. Build and flash the ADAC firmware")
            print("  2. Run authentication:")
            for gen in generations:
                suffix = f"-gen{gen}" if gen > 0 else ""
                print(f"     python3 adac_host.py --key {output_dir}/private-key{suffix}.pem --generation {gen}")
        else:
            print("\nProvisioning failed!")
            sys.exit(1)
    else:
        print("Keys generated. To provision to device:")
        print(f"  nrfutil device x-provision-keys --key-file {json_path}")
        print()
        print("Or run this script with --provision flag:")
        print(f"  python3 adac_provision.py --output {output_dir} --provision")


if __name__ == "__main__":
    main()
