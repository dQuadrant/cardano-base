{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-redundant-constraints #-}
{-# OPTIONS_GHC -Wno-unused-imports #-}

module Test.Crypto.Vector.StringConstants
  ( invalidEcdsaSigLengthError,
    invalidSchnorrVerKeyLengthError,
    invalidEcdsaVerKeyLengthError,
    invalidSchnorrSigLengthError,
    cannotDecodeVerificationKeyError,
    unexpectedDecodingError,
  )
where

import Cardano.Crypto.SECP256K1.Constants
  ( SECP256K1_ECDSA_MESSAGE_BYTES,
    SECP256K1_ECDSA_PUBKEY_BYTES,
    SECP256K1_ECDSA_SIGNATURE_BYTES,
    SECP256K1_SCHNORR_PUBKEY_BYTES,
    SECP256K1_SCHNORR_SIGNATURE_BYTES,
  )
import Data.Data (Proxy (Proxy))
import GHC.TypeLits (natVal)
import Test.Crypto.Vector.VectorUtil (hexLength)

invalidEcdsaVerKeyLengthError :: String -> String
invalidEcdsaVerKeyLengthError = invalidVerKeyLengthError $ natVal $ Proxy @SECP256K1_ECDSA_PUBKEY_BYTES

invalidSchnorrVerKeyLengthError :: String -> String
invalidSchnorrVerKeyLengthError = invalidVerKeyLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_PUBKEY_BYTES

invalidVerKeyLengthError :: Integer -> String -> String
invalidVerKeyLengthError expectedLength actualKey = "decodeVerKeyDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show (hexLength actualKey)

invalidEcdsaSigLengthError :: String -> String
invalidEcdsaSigLengthError = invalidSigLengthError $ natVal $ Proxy @SECP256K1_ECDSA_SIGNATURE_BYTES

invalidSchnorrSigLengthError :: String -> String
invalidSchnorrSigLengthError = invalidSigLengthError $ natVal $ Proxy @SECP256K1_SCHNORR_SIGNATURE_BYTES

invalidSigLengthError :: Integer -> String -> String
invalidSigLengthError expectedLength actualSig = "decodeSigDSIGN: wrong length, expected " ++ show expectedLength ++ " bytes but got " ++ show (hexLength actualSig)

cannotDecodeVerificationKeyError :: String
cannotDecodeVerificationKeyError = "decodeVerKeyDSIGN: cannot decode key"

unexpectedDecodingError :: String
unexpectedDecodingError = "Test failed. Unexpected decoding error encountered."