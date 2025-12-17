.. _crypto_cmac:

Crypto: CMAC
############

.. contents::
   :local:
   :depth: 2

The CMAC sample demonstrates how to use the :ref:`PSA Crypto API <ug_psa_certified_api_overview_crypto>` to generate and verify message authentication codes using the CMAC algorithm with AES as the underlying block cipher.

Requirements
************

The sample supports the following development kits:

.. table-from-sample-yaml::

.. include:: /includes/tfm.txt

Overview
********

The sample :ref:`enables PSA Crypto API <psa_crypto_support_enable>` and configures the following Kconfig options for the cryptographic features:

* :kconfig:option:`CONFIG_PSA_WANT_KEY_TYPE_AES` - Used to enable support for the AES key type from among the supported cryptographic operations for :ref:`ug_crypto_supported_features_key_types`.
* :kconfig:option:`CONFIG_PSA_WANT_ALG_CMAC` - Used to enable support for the CMAC algorithm from among the supported cryptographic operations for :ref:`ug_crypto_supported_features_mac_algorithms`.

.. include:: /samples/crypto/aes_cbc/README.rst
   :start-after: crypto_sample_overview_driver_selection_start
   :end-before: crypto_sample_overview_driver_selection_end

Once built and run, the sample performs the following operations:

1. Initialization:

   a. The PSA Crypto API is initialized using :c:func:`psa_crypto_init`.
   #. A random 256-bit AES key is generated using :c:func:`psa_generate_key` and stored in the PSA crypto keystore.
      The key is configured with usage flags for signing and verification.

#. CMAC signing and verification:

   a. The CMAC signing operation is set up using :c:func:`psa_mac_sign_setup` with the ``PSA_ALG_CMAC`` algorithm.
   #. The message data is processed using :c:func:`psa_mac_update`.
   #. The CMAC is finalized using :c:func:`psa_mac_sign_finish`.
   #. The CMAC verification operation is set up using :c:func:`psa_mac_verify_setup`.
   #. The message data is processed again using :c:func:`psa_mac_update`.
   #. The CMAC is verified using :c:func:`psa_mac_verify_finish`.

#. Cleanup:

   a. The AES key is removed from the PSA crypto keystore using :c:func:`psa_destroy_key`.

Building and running
********************

.. |sample path| replace:: :file:`samples/crypto/cmac`

.. include:: /includes/build_and_run_ns.txt

Testing
=======

.. include:: /samples/crypto/aes_cbc/README.rst
   :start-after: crypto_sample_testing_start
   :end-before: crypto_sample_testing_end

.. code-block:: text

   *** Booting nRF Connect SDK v3.1.0-6c6e5b32496e ***
   *** Using Zephyr OS v4.1.99-1612683d4010 ***
   [00:00:00.251,159] <inf> cmac: Starting CMAC example...
   [00:00:00.251,190] <inf> cmac: Generating random AES key for CMAC...
   [00:00:00.251,342] <inf> cmac: AES key generated successfully!
   [00:00:00.251,373] <inf> cmac: Signing using the CMAC algorithm...
   [00:00:00.251,708] <inf> cmac: Signing successful!
   [00:00:00.251,739] <inf> cmac: ---- Plaintext (len: 100): ----
   [00:00:00.251,770] <inf> cmac: Content:
                                   Example string to demonstrate basic usage of CMAC signing/verification.
   [00:00:00.251,800] <inf> cmac: ---- Plaintext end  ----
   [00:00:00.251,831] <inf> cmac: ---- CMAC (len: 16): ----
   [00:00:00.251,861] <inf> cmac: Content:
                                   a1 b2 c3 d4 e5 f6 07 18  29 3a 4b 5c 6d 7e 8f 90 |........):\m~..
   [00:00:00.251,892] <inf> cmac: ---- CMAC end  ----
   [00:00:00.251,922] <inf> cmac: Verifying the CMAC signature...
   [00:00:00.252,045] <inf> cmac: CMAC verified successfully!
   [00:00:00.252,075] <inf> cmac: Example finished successfully!


