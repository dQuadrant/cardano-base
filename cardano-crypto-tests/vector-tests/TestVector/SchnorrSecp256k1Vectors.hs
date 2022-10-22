{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use head" #-}

module TestVector.SchnorrSecp256k1Vectors
  ( tests,
  
  )
where

import Cardano.Binary (DecoderError (..), decodeFull')
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (..),
    SchnorrSecp256k1DSIGN,
    SigDSIGN,
    VerKeyDSIGN,
    signDSIGN,
    verifyDSIGN,
  )
import Codec.CBOR.Read (DeserialiseFailure (..))
import Control.Exception (throw, try)
import qualified Data.ByteString.UTF8 as BSU
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase, assertBool)
import TestVector.Vectors
  ( defaultMessage,
    defaultSKey,
    defaultSchnorrSignature,
    defaultVKey,
    schnorr256k1VKeyAndSigVerifyTestVectors,
    signAndVerifyTestVectors,
    wrongMessagesAndSignaturesTestVectors,
    wrongVerificationKeyTestVectors,
  )
import Util.StringConstants (cannotDecodeVerificationKeyError, invalidSchnorrSignatureLengthError, invalidSchnorrVerificationKeyLengthError, unexpectedDecodingError)
import Util.Utils (convertToBytes, SignatureResult)
import Data.Either (isRight, isLeft)

tests :: TestTree
tests =
  testGroup
    "SchnorrSecp256k1 Test Vectors"
    [ 
      testCase "Test vector 1 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 0),
      testCase "Test vector 2 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 1),
      testCase "Test vector 3 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 2),
      testCase "Test vector 4 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 3),
      testCase "Test vector 5 - Verification should Pass when using given signature, vkey and message." $ verifyOnlyTestVector (schnorr256k1VKeyAndSigVerifyTestVectors !! 0),
      testCase "Test vector 6 - Verification should Fail when using wrong verification key." $ wrongVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 0),
      testCase "Test vector 7 - Verification should Fail when using verification key that is not on the curve." $ verificationKeyNotOnCurveTestVector (wrongVerificationKeyTestVectors !! 1),
      testCase "Test vector 8 - Verification should Fail when using wrong message but right signature." $ wrongMessageRightSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 0),
      testCase "Test vector 9 - Verification should Fail when using right message but wrong signature." $ rightMessageWrongSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 1),
      testCase "Test vector 10 - Verification should Fail when using invalid length verification key." $ invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 2),
      testCase "Test vector 11 - Verification should Fail when using invalid length verification key." $ invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 3),
      testCase "Test vector 12 - Verification should Fail when using invalid length signature." $ invalidLengthSignatureTestVector (schnorr256k1VKeyAndSigVerifyTestVectors  !! 1),
      testCase "Test vector 13 - Verification should Fail when using invalid length signature." $ invalidLengthSignatureTestVector (schnorr256k1VKeyAndSigVerifyTestVectors !! 2)
    ]

--Whole sign and verify flow test vector
signAndVerifyTestVector :: (String, String, String) -> IO ()
signAndVerifyTestVector (sKey, vKey, msg) = do
  result <- schnorrSignAndVerifyTestVector sKey vKey msg
  assertBool "Test failed. Sign and verification should be sucessful." $ isRight result

-- Parse exsiting signature and verify using vkey msg and signature only
verifyOnlyTestVector :: (String, String, String, String) -> IO ()
verifyOnlyTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr
  assertBool "Test failed. Sign and verification should be sucessful." $ isRight result

-- Use another verification to verify the message sign by another sign key
wrongVerificationKeyTestVector :: String -> IO ()
wrongVerificationKeyTestVector wrongVKey = do
  result <- schnorrSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage
  assertBool "Test failed. Sign and verification should not be sucessful when using wrong verification key." $ isLeft result

-- Sign using one message but verify using another message but right signature
wrongMessageRightSignatureTestVector :: (String, String, String) -> IO ()
wrongMessageRightSignatureTestVector (signMsg, verifyMsg, _) = do
  result <- schnorrSignAndVerify defaultSKey defaultVKey signMsg verifyMsg Nothing
  assertBool "Test failed. Verification successful on using wrong message." $ isLeft result

-- Sign using one message and verify using same message but wrong signature
rightMessageWrongSignatureTestVector :: (String, String, String) -> IO ()
rightMessageWrongSignatureTestVector (signMsg, verifyMsg, signature) = do
  result <- schnorrSignAndVerify defaultSKey defaultVKey signMsg verifyMsg (Just signature)
  assertBool "Test failed. Verification successful on using wrong signature." $ isLeft result

-- Use invalid verification key length and try to verify using vkey msg and signature only
invalidLengthVerificationKeyTestVector :: String -> IO ()
invalidLengthVerificationKeyTestVector invalidVKey = do
  result <- try (verifyOnlyWithSigTestVector defaultSKey invalidVKey defaultMessage defaultSchnorrSignature) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using wrong verification key length." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      -- Already dropped first byte when parsing vectors so for error message also drop for invalid verification key
      assertEqual "Expected wrong length error." (invalidSchnorrVerificationKeyLengthError $ drop 2 invalidVKey) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length verification key should not be successful."

-- Parse exsiting invalid signature and try to verify using vkey msg and signature only
invalidLengthSignatureTestVector :: (String, String, String, String) -> IO ()
invalidLengthSignatureTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- try (verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using wrong signature length." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertEqual "Expected wrong length error." (invalidSchnorrSignatureLengthError sigStr) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length signature should not be successful."

-- Use verification key that is not on the curve
verificationKeyNotOnCurveTestVector :: String -> IO ()
verificationKeyNotOnCurveTestVector wrongVKey = do
  result <- try (verifyOnlyWithSigTestVector defaultSKey wrongVKey defaultMessage defaultSchnorrSignature) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using verification key not on the curve." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertEqual "Expected cannot decode key error." cannotDecodeVerificationKeyError err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Simple sign and verify test vector function with sKey, vKey and message in string
schnorrSignAndVerifyTestVector :: String -> String -> String -> IO SignatureResult
schnorrSignAndVerifyTestVector sKeyStr vKeyStr signMsg = schnorrSignAndVerify sKeyStr vKeyStr signMsg signMsg Nothing

-- Simple verify only test vector with verification message and signature in string
verifyOnlyWithSigTestVector :: String -> String -> String -> String -> IO SignatureResult
verifyOnlyWithSigTestVector sKeyStr vKeyStr verifyMsg sig = schnorrSignAndVerify sKeyStr vKeyStr verifyMsg verifyMsg (Just sig)

-- Sign and verify flow with optional message hash for sign and verify, optional signature and use them appropriately for sign and verify
schnorrSignAndVerify :: String -> String -> String -> String -> Maybe String -> IO SignatureResult
schnorrSignAndVerify sKeyStr vKeyStr signMsg verifyMsg sigM = do
  sig <- case sigM of
    Just sig' -> parseSchnorrSignature sig'
    Nothing -> schnorrSign sKeyStr signMsg
  schnorrVerify vKeyStr verifyMsg sig

-- Sign the message hash by parsing the sign key in string
schnorrSign :: String -> String -> IO (SigDSIGN SchnorrSecp256k1DSIGN)
schnorrSign sKeyStr msg = do
  sKey <- parseSchnorrSignKey sKeyStr
  pure $ signDSIGN () (BSU.fromString msg) sKey

-- Verify using vKey in string parse it, use message hash and signature
-- to verify it and return results
schnorrVerify :: String -> String -> SigDSIGN SchnorrSecp256k1DSIGN -> IO SignatureResult
schnorrVerify vKeyStr msg sig = do
  vKey <- parseSchnorrVerKey vKeyStr
  pure $ verifyDSIGN () vKey (BSU.fromString msg) sig

-- Convert vKeyInHex to appropirate vKey
parseSchnorrVerKey :: String -> IO (VerKeyDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrVerKey vKeyHex = do
  -- Drop first byte that is not used by schnorr
  vKeyBytes <- convertToBytes $ drop 2 vKeyHex
  let vKeyE = decodeFull' vKeyBytes
  case vKeyE of
    Left err -> throw err
    Right vKey -> pure vKey

-- Convert sKeyInHex to appropirate sKey
parseSchnorrSignKey :: String -> IO (SignKeyDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrSignKey sKeyHex = do
  sKeyBytes <- convertToBytes sKeyHex
  let sKeyE = decodeFull' sKeyBytes
  case sKeyE of
    Left err -> throw err
    Right sKey -> pure sKey

-- Convert sigInHex to appropirate signature
parseSchnorrSignature :: String -> IO (SigDSIGN SchnorrSecp256k1DSIGN)
parseSchnorrSignature sigHex = do
  sigBytes <- convertToBytes sigHex
  let sigE = decodeFull' sigBytes :: Either DecoderError (SigDSIGN SchnorrSecp256k1DSIGN)
  case sigE of
    Left err -> throw err
    Right sig -> pure sig