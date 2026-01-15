.. _adac_kms_backend_script:

ADAC KMS Backend Script
#######################

.. contents::
   :local:
   :depth: 2

This Python script implements the nrfutil-kms subprocess protocol for ADAC (Authenticated Debug Access Control) key management on nRF54L Series devices.

Overview
********

The script acts as a subprocess backend for nrfutil-kms, allowing nrfutil-device to perform ADAC operations using locally stored Ed25519 keys.
It listens on stdin for JSON messages and responds on stdout, following the nrfutil-kms subprocess protocol.

Features:

* Public key retrieval for ADAC authentication
* Ed25519 signing for challenge-response authentication
* Support for multiple key generations (gen0-gen3)
* Compatible with nrfutil-device ADAC commands

Requirements
************

The script requires the following Python dependencies:

* Python's cryptographic library for Ed25519 key operations:

  .. code-block:: console

     python3 -m pip install cryptography

Using the script
****************

Setting up the backend
======================

1. Generate ADAC keys using the ADAC sample's provisioning script:

   .. code-block:: console

      cd nrf/samples/tfm/adac/scripts
      python3 adac_provision.py --output output/

2. Register the subprocess backend with nrfutil-kms:

   .. code-block:: console

      nrfutil kms service add subprocess adac_local \
        --key-template "{key_name}" \
        --command python3 /absolute/path/to/adac_kms_backend.py /absolute/path/to/keys

   Replace the paths with absolute paths to the script and key directory.

3. Test the backend configuration:

   .. code-block:: console

      nrfutil kms service test adac_local gen0

   This should return the public key for generation 0.

Using with nrfutil-device
=========================

Once the backend is registered, use nrfutil-device commands with the ``--kms`` flag:

.. code-block:: console

   # Perform ADAC lifecycle change
   nrfutil device x-adac-lcs-change --life-cycle test --serial-number XXXX --kms adac_local

Key name mapping
================

The backend maps key names to PEM files:

.. list-table:: Key name to file mapping
   :header-rows: 1
   :widths: 20 40 40

   * - Key name
     - Private key file
     - Public key file
   * - ``gen0`` or ``0``
     - ``private-key.pem``
     - ``public-key.pem``
   * - ``gen1`` or ``1``
     - ``private-key-gen1.pem``
     - ``public-key-gen1.pem``
   * - ``gen2`` or ``2``
     - ``private-key-gen2.pem``
     - ``public-key-gen2.pem``
   * - ``gen3`` or ``3``
     - ``private-key-gen3.pem``
     - ``public-key-gen3.pem``

Subprocess protocol
*******************

The script implements the nrfutil-kms subprocess JSON protocol:

Request types
=============

public-key request
------------------

Returns the Ed25519 public key for a given key name.

.. code-block:: json

   { "type": "public-key", "version": "1", "keyName": "gen0" }

Response:

.. code-block:: json

   { "type": "public-key", "version": "1", "keyType": "ed25519", "base64Bytes": "..." }

sign request
------------

Signs data with the private key using pure Ed25519.

.. code-block:: json

   { "type": "sign", "version": "1", "keyName": "gen0", "base64Bytes": "..." }

Response:

.. code-block:: json

   { "type": "sign", "version": "1", "base64Bytes": "..." }

finish request
--------------

Cleanly exits the subprocess.

.. code-block:: json

   { "type": "finish", "version": "1" }

error response
--------------

Returned when an error occurs:

.. code-block:: json

   { "type": "error", "version": "1", "reason": "..." }

Backend configuration
*********************

The backend configuration is stored in ``~/.nrfutil/config/nrfutil-kms/config.json``:

.. code-block:: json

   {
     "adac_local": {
       "type": "subprocess",
       "version": "1",
       "executable": "python3",
       "arguments": ["/path/to/adac_kms_backend.py", "/path/to/keys"],
       "key_template": "{key_name}"
     }
   }

Related documentation
*********************

* :ref:`adac_sample` - ADAC sample application
* :ref:`generate_psa_key_attributes_script` - PSA key attributes generator
* `nRF Util documentation <nRF Util_>`_ - nrfutil-kms and nrfutil-device commands

