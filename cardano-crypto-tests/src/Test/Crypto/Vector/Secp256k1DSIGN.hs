{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}

module Test.Crypto.Vector.Secp256k1DSIGN
  ( tests,
  )
where

import Cardano.Binary (DecoderError (DecoderErrorDeserialiseFailure), FromCBOR, decodeFull')
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm
      ( ContextDSIGN,
        SigDSIGN,
        SignKeyDSIGN,
        Signable,
        VerKeyDSIGN,
        deriveVerKeyDSIGN,
        signDSIGN,
        verifyDSIGN
      ),
    EcdsaSecp256k1DSIGN,
    MessageHash,
    SchnorrSecp256k1DSIGN,
    hashAndPack,
    toMessageHash,
  )
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import Codec.CBOR.Read (DeserialiseFailure (..))
import Control.Monad (forM_)
import Data.ByteString (ByteString)
import Data.Either (isLeft, isRight)
import Data.Maybe (isNothing)
import Data.Proxy (Proxy (..))
import Test.Crypto.Vector.StringConstants
  ( cannotDecodeVerificationKeyError,
    invalidEcdsaSigLengthError,
    invalidEcdsaVerKeyLengthError,
    invalidSchnorrSigLengthError,
    invalidSchnorrVerKeyLengthError,
    unexpectedDecodingError,
  )
import Test.Crypto.Vector.VectorUtil as Utils (HexString (..), convertToBytes, drop)
import Test.Crypto.Vector.Vectors
  ( defaultMessage,
    defaultSKey,
    ecdsaMismatchMessageAndSignature,
    ecdsaVerKeyAndSigVerifyTestVectors,
    ecdsaWrongLengthSigTestVectorsRaw,
    schnorrMismatchMessageAndSignature,
    schnorrVerKeyAndSigVerifyTestVectors,
    schnorrWrongLengthSigTestVectorsRaw,
    signAndVerifyTestVectors,
    verKeyNotOnCurveTestVectorRaw,
    wrongEcdsaVerKeyTestVector,
    wrongLengthMessageHashTestVectors,
    wrongLengthVerKeyTestVectorsRaw,
    wrongSchnorrVerKeyTestVector,
  )
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

ecdsaProxy :: Proxy EcdsaSecp256k1DSIGN
ecdsaProxy = Proxy

schnorrProxy :: Proxy SchnorrSecp256k1DSIGN
schnorrProxy = Proxy

tests :: TestTree
tests =
  testGroup
    "Secp256k1 Test Vectors"
    [ -- Note : Proxies are here repetead due to specific test vectors need to be used with specific proxy
      testGroup
        "EcdsaSecp256k1"
        [ signAndVerifyTest ecdsaProxy,
          verifyOnlyTest ecdsaProxy ecdsaVerKeyAndSigVerifyTestVectors,
          wrongMessageHashLengthTest,
          mismatchSignKeyVerKeyTest ecdsaProxy wrongEcdsaVerKeyTestVector,
          mismatchMessageSignatureTest ecdsaProxy ecdsaMismatchMessageAndSignature,
          verKeyNotOnCurveParserTest ecdsaProxy verKeyNotOnCurveTestVectorRaw,
          invalidLengthVerKeyParserTest ecdsaProxy wrongLengthVerKeyTestVectorsRaw invalidEcdsaVerKeyLengthError,
          invalidLengthSignatureParserTest ecdsaProxy ecdsaWrongLengthSigTestVectorsRaw invalidEcdsaSigLengthError
        ],
      testGroup
        "SchnorrSecp256k1"
        [ signAndVerifyTest schnorrProxy,
          verifyOnlyTest schnorrProxy schnorrVerKeyAndSigVerifyTestVectors,
          mismatchSignKeyVerKeyTest schnorrProxy wrongSchnorrVerKeyTestVector,
          mismatchMessageSignatureTest schnorrProxy schnorrMismatchMessageAndSignature,
          -- Drop first byte in the case of schnorr for verification key
          verKeyNotOnCurveParserTest schnorrProxy (Utils.drop 2 verKeyNotOnCurveTestVectorRaw),
          invalidLengthVerKeyParserTest schnorrProxy (map (Utils.drop 2) wrongLengthVerKeyTestVectorsRaw) invalidSchnorrVerKeyLengthError,
          invalidLengthSignatureParserTest schnorrProxy schnorrWrongLengthSigTestVectorsRaw invalidSchnorrSigLengthError
        ]
    ]

type ErrorReportFunction = String -> String

invalidLengthSignatureParserTest ::
  forall v.
  ( FromCBOR (SigDSIGN v)
  ) =>
  Proxy v ->
  [HexString] ->
  ErrorReportFunction ->
  TestTree
invalidLengthSignatureParserTest _ invalidLengthSigs errorF =
  testCase "Parsing should fail when using invalid length signatures." $
    forM_ invalidLengthSigs $ \invalidSig@(HexString hs) -> do
      let (DeserialiseFailure _ actualError) = invalidSigParserTest (Proxy @v) invalidSig
      assertEqual "Expected invalid length signature error.." (errorF hs) actualError

-- Try to parse the raw string into signature key and return the deserialize error
invalidSigParserTest ::
  forall v.
  ( FromCBOR (SigDSIGN v)
  ) =>
  Proxy v ->
  HexString ->
  DeserialiseFailure
invalidSigParserTest _ rawSig = do
  let result = fullSigParser (Proxy @v) rawSig
  case result of
    Left (DecoderErrorDeserialiseFailure _ err) -> err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Invalid signature is treated as valid."

-- Signature parser using decodeFull
fullSigParser ::
  forall v.
  ( FromCBOR (SigDSIGN v)
  ) =>
  Proxy v ->
  HexString ->
  Either DecoderError (SigDSIGN v)
fullSigParser _ (HexString hs) = (decodeFull' . convertToBytes) hs

-- Try to parse invalid length raw verification key
invalidLengthVerKeyParserTest ::
  forall v.
  ( FromCBOR (VerKeyDSIGN v)
  ) =>
  Proxy v ->
  [HexString] ->
  ErrorReportFunction ->
  TestTree
invalidLengthVerKeyParserTest _ invalidLengthVKeys errorF =
  testCase "Parsing should fail when using invalid length verification keys." $
    forM_ invalidLengthVKeys $ \invalidVKey@(HexString hs) -> do
      let (DeserialiseFailure _ actualError) = invalidVerKeyParserTest (Proxy @v) invalidVKey
      assertEqual "Expected invalid length verification key error." (errorF hs) actualError

-- Try to parse raw verification key string and e
verKeyNotOnCurveParserTest ::
  forall v.
  ( FromCBOR (VerKeyDSIGN v)
  ) =>
  Proxy v ->
  HexString ->
  TestTree
verKeyNotOnCurveParserTest _ rawVKey = testCase "Parsing should fail when trying to parse verification key not on the curve." $ do
  let (DeserialiseFailure _ actualError) = invalidVerKeyParserTest (Proxy @v) rawVKey
  assertEqual "Expected cannot decode key error." cannotDecodeVerificationKeyError actualError

-- Try to parse the raw string into verification key and return the deserialize error
invalidVerKeyParserTest ::
  forall v.
  ( FromCBOR (VerKeyDSIGN v)
  ) =>
  Proxy v ->
  HexString ->
  DeserialiseFailure
invalidVerKeyParserTest _ rawVKey = do
  let result = fullVerKeyParser (Proxy @v) rawVKey
  case result of
    Left (DecoderErrorDeserialiseFailure _ err) -> err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Invalid verification key is treated as valid."

-- Vkey parser using decodeFull
fullVerKeyParser ::
  forall v.
  ( FromCBOR (VerKeyDSIGN v)
  ) =>
  Proxy v ->
  HexString ->
  Either DecoderError (VerKeyDSIGN v)
fullVerKeyParser _ (HexString hs) = (decodeFull' . convertToBytes) hs

-- Use mismatch messages and signature vectors to test how verification behaves on wrong message or wrong signature
mismatchMessageSignatureTest ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a
  ) =>
  Proxy v ->
  [(ByteString, VerKeyDSIGN v, SigDSIGN v)] ->
  TestTree
mismatchMessageSignatureTest _ mismatchMessageSignatureVectors =
  testCase "Verification should not be successful when using mismatch message, signature and vice versa." $
    forM_
      mismatchMessageSignatureVectors
      ( \(msg, vKey, sig) -> do
          let result = verifyDSIGN () vKey (toSignable (Proxy @v) msg) sig
          assertBool "Test Failed. Verification should not be successful." $ isLeft result
      )

-- Use mismatch verification key for the signature generated by another signing key
mismatchSignKeyVerKeyTest ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a,
    FromCBOR (SignKeyDSIGN v)
  ) =>
  Proxy v ->
  VerKeyDSIGN v ->
  TestTree
mismatchSignKeyVerKeyTest _ vKey = testCase "Verification should not be successful when using wrong verification key." $ do
  let result = signAndVerifyWithVkey (Proxy @v) defaultSKey vKey defaultMessage
  assertBool "Test failed. Verification should not be successful." $ isLeft result

-- Wrong message hash length parser test for ecdsa
wrongMessageHashLengthTest :: TestTree
wrongMessageHashLengthTest = testCase "toMessageHash should return Nothing when using invalid length message hash." $
  forM_ wrongLengthMessageHashTestVectors $ \msg -> do
    let msgHash = toMessageHash msg
    assertBool "Test failed. Wrong message hash length is treated as right." $ isNothing msgHash

-- Test for vKey, message and signature test vectors without using sign key
verifyOnlyTest ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a
  ) =>
  Proxy v ->
  (VerKeyDSIGN v, ByteString, SigDSIGN v) ->
  TestTree
verifyOnlyTest _ (vKey, msg, sig) = testCase "Verification only should be successful." $ verifyOnly (Proxy @v) vKey msg sig

-- Sign using givne sKey and verify it
signAndVerifyTest ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a,
    FromCBOR (SignKeyDSIGN v)
  ) =>
  Proxy v ->
  TestTree
signAndVerifyTest _ =
  testCase "Signing and verifications should be successful." $
    mapM_ (uncurry $ signAndVerify (Proxy @v)) signAndVerifyTestVectors

-- Sign a message using sign key, dervive verification key and check the signature
-- Used for testing whole sign and verification flow
signAndVerify ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a
  ) =>
  Proxy v ->
  SignKeyDSIGN v ->
  ByteString ->
  IO ()
signAndVerify _ sKey msg = do
  let vKey = deriveVerKeyDSIGN sKey
      result = signAndVerifyWithVkey (Proxy @v) sKey vKey msg
  assertBool "Test failed. Sign and verification should be successful." $ isRight result

-- Sign a message using sign key, dervive verification key and check the signature
-- Used for testing whole sign and verification flow
signAndVerifyWithVkey ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a
  ) =>
  Proxy v ->
  SignKeyDSIGN v ->
  VerKeyDSIGN v ->
  ByteString ->
  Either String ()
signAndVerifyWithVkey _ sKey vKey msg =
  let sig = signDSIGN () (toSignable (Proxy @v) msg) sKey
   in verifyDSIGN () vKey (toSignable (Proxy @v) msg) sig

-- Use alreday given signature, message and vkey to verify the signature
verifyOnly ::
  forall v a.
  ( DSIGNAlgorithm v,
    ContextDSIGN v ~ (),
    Signable v a,
    ToSignable v a
  ) =>
  Proxy v ->
  VerKeyDSIGN v ->
  ByteString ->
  SigDSIGN v ->
  IO ()
verifyOnly _ vKey msg sig = do
  let result = verifyDSIGN () vKey (toSignable (Proxy @v) msg) sig
  assertBool "Test failed. Sign and verification should be successful." $ isRight result

-- Class for supplying required message format according to signature algorithm used
class ToSignable v a | v -> a where
  toSignable :: Signable v a => Proxy v -> ByteString -> a

instance ToSignable EcdsaSecp256k1DSIGN MessageHash where
  toSignable _ bs = hashAndPack (Proxy @SHA3_256) bs

instance ToSignable SchnorrSecp256k1DSIGN ByteString where
  toSignable _ bs = bs
