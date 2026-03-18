.. _tfm_manufacturing_application:

TF-M Manufacturing Application
###############################

.. contents::
   :local:
   :depth: 2

Overview
********

This sample is a reference manufacturing application for the nRF54LV10A SoC.
It implements the complete 12-step manufacturing provisioning flow, running as
a TF-M non-secure application after the full boot chain (BL1 → BL2/MCUboot →
TF-M) has executed.

The application is designed to be **idempotent**: every reboot executes all
12 steps. Each step checks whether the required operation has already been
performed and skips it cleanly if so. This makes the application immune to
power drops at any point in the manufacturing flow.

The application is intended as a **reference** that Nordic customers can read,
understand, and adapt. Each manufacturing step is isolated in its own source
file. TODOs and stubs are documented with integration guidance where a TF-M
platform service must be added.

Manufacturing Steps
*******************

.. list-table::
   :header-rows: 1

   * - Step
     - Description
     - Source file
   * - 1
     - Show LCS at entry — verify valid manufacturing state
     - ``src/lcs.c``
   * - 2
     - Validate no IKG seed or KeyRAM random present (MTEST LCS only)
     - ``src/ikg_check.c``
   * - 3
     - Validate digests of all sub-images (BL1, BL2, mfg app, app candidate)
     - ``src/image_validation.c``
   * - 4
     - Provision and verify secure-boot and ADAC public keys
     - ``src/key_provisioning.c``
   * - 5
     - Block erase-all via UICR.ERASEPROTECT (optional, see CONFIG_BLOCK_ERASE_ALL)
     - ``src/erase_protection.c``
   * - 6
     - Advance LCS to 'PROT Provisioning'
     - ``src/lcs.c``
   * - 7
     - Provision KeyRAM random data (KMU slots 248, 249)
     - ``src/huk_provisioning.c``
   * - 8
     - Provision IKG seed; log IAK / MKEK / MEXT key identifiers
     - ``src/huk_provisioning.c``
   * - 9
     - End product tests (placeholder)
     - ``src/product_tests.c``
   * - 10
     - Provision remaining assets and device enrolment (placeholder)
     - ``src/asset_provisioning.c``
   * - 11
     - Advance LCS to 'Secured'
     - ``src/lcs.c``
   * - 12
     - Revoke manufacturing app key; reboot to install target application
     - ``src/main.c``, ``src/key_provisioning.c``

Requirements
************

* nRF54LV10 DK (PCA10170)
* nRF Connect SDK v2.9.0 or later
* West build environment

Key Generation
**************

The manufacturing application must be built with your own production public
keys. The placeholder files in the ``keys/`` directory must be replaced before
manufacturing end products.

Generating Ed25519 key pairs
============================

.. code-block:: bash

   # Generate UROT generation-0 key pair
   openssl genpkey -algorithm Ed25519 -out keys/urot_privkey_gen0.pem
   openssl pkey -in keys/urot_privkey_gen0.pem -pubout -out keys/urot_pubkey_gen0.pem

   # Generate UROT generation-1 key pair
   openssl genpkey -algorithm Ed25519 -out keys/urot_privkey_gen1.pem
   openssl pkey -in keys/urot_privkey_gen1.pem -pubout -out keys/urot_pubkey_gen1.pem

.. warning::

   Private key files (``urot_privkey_*.pem``) must never be placed in the
   ``keys/`` directory or committed to source control. The manufacturing
   application validates at runtime that no private key material has been
   accidentally included.

Generating key verification messages
=====================================

Each public key must have a corresponding pre-signed verification message in
``keys/key_verification_msgs/``. The manufacturing application uses these to
confirm that the key stored in the KMU is correct and functional.

.. code-block:: bash

   # Define a fixed verification message (must match MFG_KEY_VERIFY_MESSAGE
   # in src/key_provisioning.c):
   echo -n "manufacturing_key_verification_v1" > /tmp/verify_msg.bin

   # Sign the message with each private key:
   openssl pkeyutl -sign \
       -inkey keys/urot_privkey_gen0.pem \
       -rawin -in /tmp/verify_msg.bin \
       -out keys/key_verification_msgs/urot_pubkey_gen0_signed.msg

   openssl pkeyutl -sign \
       -inkey keys/urot_privkey_gen1.pem \
       -rawin -in /tmp/verify_msg.bin \
       -out keys/key_verification_msgs/urot_pubkey_gen1_signed.msg

Building and Running
********************

Building with placeholder keys (development only):

.. code-block:: bash

   west build -b nrf54lv10dk/nrf54lv10a/cpuapp/ns \
       nrf/samples/tfm/manufacturing_application \
       --sysbuild

Building with production keys and image digests:

.. code-block:: bash

   west build -b nrf54lv10dk/nrf54lv10a/cpuapp/ns \
       nrf/samples/tfm/manufacturing_application \
       --sysbuild \
       -- \
       -DMFG_BL1_DIGEST=<sha256_hex_of_bl1_image> \
       -DMFG_BL2A_DIGEST=<sha256_hex_of_bl2_slot_a> \
       -DMFG_BL2B_DIGEST=<sha256_hex_of_bl2_slot_b> \
       -DMFG_APP_CANDIDATE_DIGEST=<sha256_hex_of_app_candidate>

Flashing:

.. code-block:: bash

   west flash --erase

Expected Serial Output (Development Run)
*****************************************

The following shows an expected development run where placeholder keys are
used and platform service stubs log their status::

   Checking LCS, nrf/samples/tfm/manufacturing_application/src/lcs.c, line: 73
   Current LCS = 'Manufacturing and Test'

   Checking IKG seed presence, nrf/samples/tfm/manufacturing_application/src/ikg_check.c, line: 107
   Verifying KMU IKG seed slots... OK (empty)
   Verifying KMU KeyRAM random slot 248... OK (empty)
   Verifying KMU KeyRAM random slot 249... OK (empty)

   Validating images, nrf/samples/tfm/manufacturing_application/src/image_validation.c, line: 178
   Validating Bootloader 1... SKIP (BL1 in Secure flash — platform service not yet implemented)
   Validating Bootloader 2, slot A... SKIP (BL2 in Secure flash — platform service not yet implemented)
   Validating Bootloader 2, slot B... SKIP (BL2 in Secure flash — platform service not yet implemented)
   Validating Manufacturing application (self-check)... SKIP (TLV parser not yet implemented)
   Validating Application candidate... SKIP (no expected digest provided at build time)

   Validating secure boot and ADAC keys, nrf/samples/tfm/manufacturing_application/src/key_provisioning.c, line: 166
   Location to place keys: 'keys' directory.
   Validating urot_pubkey_gen0.pem... FAIL (does not contain a public key — placeholder detected)
   Generate your own keys and build this app again.

   Try to recover the device.
   ...
   Execution suspended.

Open Questions
**************

See the section below for unresolved design questions that must be answered
before this application is used in mass production.

Configuration
*************

.. option:: CONFIG_BLOCK_ERASE_ALL

   When enabled, programs ``UICR.ERASEPROTECT.PROTECT0`` and
   ``UICR.ERASEPROTECT.PROTECT1`` to ``0x50FA50FA`` during Step 5, permanently
   blocking the SWD erase-all command. Default: ``n``.

   .. warning::

      This operation is irreversible without authenticated erase-all.
      Do not enable for engineering devices.

.. option:: CONFIG_MFG_APP_KEY_KMU_SLOT

   KMU slot holding the manufacturing application authentication key. This key
   is revoked in Step 12. Default: ``122``.

.. option:: CONFIG_MFG_UROT_KEY_GEN0_KMU_SLOT

   First KMU slot for UROT generation-0 public key (Ed25519, 2 slots).
   Default: ``120``.

.. option:: CONFIG_MFG_UROT_KEY_GEN1_KMU_SLOT

   First KMU slot for UROT generation-1 public key (Ed25519, 2 slots).
   Default: ``124``.

Open Questions and Known Stubs
*******************************

The following issues must be resolved before this application can be used in
a real manufacturing line. Each item identifies the stub location.

**OQ-1: LCS advancement from NS (src/lcs.c — lcs_advance)**

   ``psa_rot_lifecycle_state()`` is available from TF-M NS but there is no
   standard PSA API for advancing the LCS. On Nordic devices the LCS is written
   by ``update_life_cycle_state()`` (``bl_storage.h``), which requires Secure
   flash access. A TF-M platform service must be added that exposes this
   operation via IPC. Until then, Steps 6 and 11 log a stub message.

**OQ-2: UICR.ERASEPROTECT access from NS (src/erase_protection.c)**

   ``UICR`` is mapped only in the Secure address space (``0xFFD000``). Reading
   and writing ``ERASEPROTECT.PROTECT0/PROTECT1`` requires a TF-M platform
   service. Both the read stub (``platform_svc_eraseprotect_read``) and write
   stub (``platform_svc_eraseprotect_activate``) return ``-ENOSYS`` until
   implemented. Step 5 currently logs the limitation and continues.

**OQ-3: KeyRAM random provisioning from NS (src/huk_provisioning.c — step 7)**

   ``cracen_provision_prot_ram_inv_slots()`` is a Secure-side CRACEN driver
   function. A TF-M platform service wrapping it must be added. Alternatively,
   if the CRACEN PSA driver proxies the necessary ``psa_import_key()`` call,
   direct PSA provisioning from NS may work. Investigate and implement.

**OQ-4: IKG seed provisioning from NS (src/huk_provisioning.c — step 8)**

   ``hw_unique_key_write_random()`` (``nrf/include/hw_unique_key.h``) is a
   Secure-side library function. A TF-M platform service exposing this must be
   added. Step 8 is currently stubbed.

**OQ-5: Image validation for Secure-side images (src/image_validation.c)**

   BL1 and BL2 (MCUboot) reside in Secure flash that the NS application cannot
   read. A TF-M platform service that hashes a given Secure flash range and
   returns the digest to the NS caller is required for Steps 3 BL1 and BL2
   validation. The manufacturing app self-validation requires a minimal MCUboot
   TLV parser; implementation is pending inclusion of the MCUboot ``bootutil``
   headers.

**OQ-6: Key verification message format and content (src/key_provisioning.c)**

   The fixed message string ``"manufacturing_key_verification_v1"`` used in
   ``MFG_KEY_VERIFY_MESSAGE`` is a placeholder. The canonical content and
   encoding must be defined, then the ``keys/key_verification_msgs/*.msg``
   files regenerated accordingly.

**OQ-7: MANUFACTURING_APP_KEY identity and slot**

   Step 12 revokes the key in ``CONFIG_MFG_APP_KEY_KMU_SLOT`` (default 122).
   This key must be pre-provisioned (e.g. by BL1/BL2) before the manufacturing
   app runs. Confirm the slot assignment and revocation policy with the
   bootloader team.

**OQ-8: KeyRAM random naming**

   The name "KeyRAM random" (referencing KMU slots 248 and 249,
   ``PROTECTED_RAM_INVALIDATION_DATA_SLOT1/2``) is not intuitive. A more
   descriptive name should be agreed and the variable names / log strings
   updated.

**OQ-9: Skippable steps when entering in PROT Provisioning LCS**

   The comment in Step 1 references a TBD optimisation: when the device boots
   directly into ``PROT Provisioning`` (e.g. after a partial previous run),
   some steps can be skipped. Step 2 is already guarded by the LCS check in
   ``main.c``. Confirm which additional steps (e.g. Step 5) can be safely
   skipped in that state.

**OQ-10: PSA Instance ID format**

   Step 8 logs ``PSA Instance ID: <TBD>``. The format must be agreed upon
   (hex string, base64, or decimal) and the computation implemented. The
   standard definition is ``0x01 || SHA-256(IAK_public_key)`` per the PSA
   attestation specification.
