# ADAC Host Scripts for nRF54L15

These scripts enable Authenticated Debug Access Control (ADAC) on the nRF54L15.

## Prerequisites

1. **Python packages:**
   ```bash
   pip install pylink-square pynacl cryptography
   ```

   Note: Uses Ed25519ph (prehashed Ed25519) as per ADAC specification.

2. **nRF Command Line Tools:**
   Download from [Nordic's website](https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools)

3. **nRF Util** (for KMU provisioning):
   Download from [Nordic's website](https://www.nordicsemi.com/Products/Development-tools/nRF-Util)

## Quick Start

### 1. Generate and Provision Keys

The easiest way to set up ADAC is using the provisioning script:

```bash
cd /home/dag/ncs/nrf/samples/tfm/adac/scripts
python3 adac_provision.py --output output/ --provision
```

This will:
- Generate 4 generations of Ed25519 key pairs
- Create a JSON file for KMU provisioning
- Provision all keys to the device's KMU

### 2. Build and Flash Firmware

```bash
cd /home/dag/ncs
source .venv/bin/activate
export ZEPHYR_SDK_INSTALL_DIR=/home/dag/ncs/toolchains/e9dba88316/opt/zephyr-sdk

west build -b nrf54l15dk/nrf54l15/cpuapp/ns -p always nrf/samples/tfm/adac
west flash
```

### 3. Run Authentication

```bash
python3 adac_host.py --key output/private-key.pem --generation 0
```

## Key Provisioning

ADAC requires public keys (ROTPKs) to be provisioned to the device's KMU before authentication can work.

### Provisioning Script

The `adac_provision.py` script handles key generation and provisioning:

```bash
# Generate all 4 generations and provision to device
python3 adac_provision.py --output output/ --provision

# Generate keys only (provision manually later)
python3 adac_provision.py --output output/

# Generate specific generations only
python3 adac_provision.py --output output/ --generations 0 2

# Use existing keys (skip generation)
python3 adac_provision.py --output output/ --provision --skip-keygen

# Provision to specific probe
python3 adac_provision.py --output output/ --provision --probe 123456789
```

### Manual Provisioning

If you prefer to provision manually:

```bash
# Generate keys
python3 adac_provision.py --output output/

# Provision using nrfutil
nrfutil device x-provision-keys --key-file output/adac_keys.json
```

### KMU Slot Layout

Each Ed25519 public key (32 bytes) requires 2 consecutive 16-byte KMU slots:

| Generation | KMU Slots | Private Key File | Public Key File |
|------------|-----------|------------------|-----------------|
| 0 | 207-208 | private-key.pem | public-key.pem |
| 1 | 209-210 | private-key-gen1.pem | public-key-gen1.pem |
| 2 | 211-212 | private-key-gen2.pem | public-key-gen2.pem |
| 3 | 213-214 | private-key-gen3.pem | public-key-gen3.pem |

## Key Generations and Revocation

ADAC supports up to 4 key generations for key rotation and revocation. This allows
you to update keys over time while ensuring older (potentially compromised) keys
cannot be used.

### Generating Keys for Different Generations

```bash
# Generate all 4 generations
python3 adac_provision.py --output output/

# Or generate individual keys
python3 adac_cert.py output/ --generation 0
python3 adac_cert.py output/ --generation 1
python3 adac_cert.py output/ --generation 2
python3 adac_cert.py output/ --generation 3
```

### Authenticating with a Specific Generation

```bash
# Authenticate with generation 0 (default)
python3 adac_host.py --key output/private-key.pem

# Authenticate with generation 2
python3 adac_host.py --key output/private-key-gen2.pem --generation 2
```

### Automatic Key Revocation

When `CONFIG_TFM_ADAC_AUTO_REVOKE=y` (default), authenticating with key generation N
will automatically and permanently revoke all generations < N in the KMU.

**Example:**
1. Device has generations 0, 1, 2, 3 provisioned
2. User authenticates with generation 2
3. Generations 0 and 1 are revoked in KMU (hardware-enforced, cannot be restored)
4. Future authentications can only use generations 2 or 3

### Initial Revocation via Kconfig

Use `CONFIG_TFM_ADAC_AUTH_KEY_GEN` to pre-revoke older generations at boot:

```kconfig
# In prj.conf - revoke generations 0 and 1 at boot
CONFIG_TFM_ADAC_AUTH_KEY_GEN=2
```

### Kconfig Options

| Option | Default | Description |
|--------|---------|-------------|
| `CONFIG_TFM_ADAC_ROTPK_KMU_SLOT_BASE` | 207 | Base KMU slot for ROTPKs |
| `CONFIG_TFM_ADAC_AUTH_KEY_GEN` | 0 | Initial minimum valid generation |
| `CONFIG_TFM_ADAC_AUTO_REVOKE` | y | Auto-revoke older generations on auth |

## How It Works

The authentication flow:

1. **Trigger**: Host sends a trigger word to wake up ADAC
2. **Discovery** (optional): Query device capabilities
3. **Auth Start**: Device generates a random challenge vector
4. **Auth Response**: Host sends:
   - Certificate (containing public key, signed with pure Ed25519)
   - Token (challenge signature, signed with pure Ed25519)
5. **Verification**: Device verifies certificate chain and token signature
6. **Revocation**: If auto-revoke enabled and generation > 0, older generations are revoked
7. **Unlock**: On success, debug protection (APPROTECT) is disabled

## Script Files

| File | Description |
|------|-------------|
| `adac_provision.py` | Generate keys and provision to KMU |
| `adac_cert.py` | Generate Ed25519 keys and certificates |
| `adac_host.py` | Perform ADAC authentication via CTRL-AP mailbox |

## nrfutil-kms Integration

The `adac_kms_backend.py` script in `nrf/scripts/nrf_provision/adac/` implements the
nrfutil-kms subprocess protocol, allowing you to use nrfutil-device for ADAC operations
with locally stored keys.

For full documentation, see the script's README at:
`nrf/scripts/nrf_provision/adac/README.rst`

### Quick Start

1. **Generate keys** (if not already done):

   ```bash
   python3 adac_provision.py --output output/
   ```

2. **Register the subprocess backend** with nrfutil-kms:

   ```bash
   # Get the absolute path to the script
   SCRIPT_PATH=$(realpath ../../scripts/nrf_provision/adac/adac_kms_backend.py)
   KEY_PATH=$(realpath output/)

   nrfutil kms service add subprocess adac_local \
     --key-template "{key_name}" \
     --command python3 $SCRIPT_PATH $KEY_PATH
   ```

3. **Test the backend**:

   ```bash
   nrfutil kms service test adac_local gen0
   ```

4. **Use with nrfutil-device**:

   ```bash
   nrfutil device x-adac-lcs-change --life-cycle test --serial-number XXX --kms adac_local
   ```

### Key Name Mapping

The subprocess backend maps key names to PEM files:

| key_name | Private Key File | Public Key File |
|----------|------------------|-----------------|
| `gen0` | `private-key.pem` | `public-key.pem` |
| `gen1` | `private-key-gen1.pem` | `public-key-gen1.pem` |
| `gen2` | `private-key-gen2.pem` | `public-key-gen2.pem` |
| `gen3` | `private-key-gen3.pem` | `public-key-gen3.pem` |

You can also use numeric key names (`0`, `1`, `2`, `3`).

## Troubleshooting

### "No valid ROTPKs found"
- Keys have not been provisioned to the KMU
- Run `python3 adac_provision.py --output output/ --provision`

### "Timeout waiting for RX data"
- Ensure firmware is flashed and running
- Check device is connected and powered
- Try resetting the device

### "UNAUTHORIZED" status
- The public key on the device doesn't match your private key
- Re-provision keys using `adac_provision.py`
- Ensure certificate was generated with matching private key

### "Key generation revoked"
- The key generation you're trying to use has been revoked
- Use a newer (non-revoked) key generation
- Revocation is permanent and cannot be undone

### nrfutil errors
- Ensure nRF Util is installed and in PATH
- Try `nrfutil --version` to verify installation
- Check device is connected: `nrfutil device list`

### pynrfjprog errors
- Install nRF Command Line Tools
- Ensure J-Link drivers are installed
- Try `nrfjprog --ids` to verify device connection

## CTRL-AP Mailbox Protocol

The ADAC communication uses the CTRL-AP mailbox. Base address: `0x50052000`

| Register | Offset | Address | Description |
|----------|--------|---------|-------------|
| RXDATA | 0x400 | 0x50052400 | Debugger writes, device reads |
| RXSTATUS | 0x404 | 0x50052404 | RX pending (device hasn't read yet) |
| TXDATA | 0x480 | 0x50052480 | Device writes, debugger reads |
| TXSTATUS | 0x484 | 0x50052484 | TX pending (device has written data) |

**Note:** The naming is from the device's perspective:
- **RXDATA**: Data the device receives (we write here)
- **TXDATA**: Data the device transmits (we read here)

### Packet Format

**Request:** `[reserved:16][command:16][data_count:32][data...]`

**Response:** `[reserved:16][status:16][data_count:32][data...]`

### Commands

| Command | Value | Description |
|---------|-------|-------------|
| DISCOVERY | 0x01 | Query device capabilities |
| AUTH_START | 0x02 | Get authentication challenge |
| AUTH_RESPONSE | 0x03 | Send certificate and token |
| CLOSE_SESSION | 0x04 | Close debug session |
| LOCK_DEBUG | 0x05 | Lock debug access |
