It contains tests for vectors that are used to test secp256k1 functionalities.

**ECDSA**
    - Signing and verification successful
    - Invalid length for required parameters check
    - Signing and verification of pre-image message by hashing it
    - Invalid message hash length check for ecdsa
    - Invalid verification key check
    - Invalid message hash check
    - Invalid signature check

**Schnorr**
    - Signing and verification successful
    - Invalid length for required parameters check
    - Invalid verification key check
    - Invalid message check
    - Invalid signature check