{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}

{-# HLINT ignore "Use head" #-}

module TestVector.EcdsaSecp256k1Vectors
  ( tests,
     )
where

-- from utf8-string
import Cardano.Binary (DecoderError (..), decodeFull')
import Cardano.Crypto.DSIGN
  ( DSIGNAlgorithm (..),
    EcdsaSecp256k1DSIGN,
    MessageHash,
    SigDSIGN,
    VerKeyDSIGN,
    hashAndPack,
    signDSIGN,
    toMessageHash,
    verifyDSIGN,
  )
import Cardano.Crypto.Hash.SHA3_256 (SHA3_256)
import Codec.CBOR.Read (DeserialiseFailure (..))
import Control.Exception (throw, try)
import qualified Data.ByteString.UTF8 as BSU
import Data.Proxy (Proxy (..))
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertEqual, testCase, assertBool)
import TestVector.Vectors
  ( defaultEcdsaSignature,
    defaultMessage,
    defaultSKey,
    defaultVKey,
    ecdsa256k1VKeyAndSigVerifyTestVectors,
    signAndVerifyTestVectors,
    wrongLengthMessageHashTestVectors,
    wrongMessagesAndSignaturesTestVectors,
    wrongVerificationKeyTestVectors,
  )
import Util.StringConstants
  ( cannotDecodeVerificationKeyError,
    invalidEcdsaSignatureLengthError,
    invalidEcdsaVerificationKeyLengthError,
    unexpectedDecodingError,
  )
import Util.Utils (convertToBytes, SignatureResult)
import Data.Either (isRight, isLeft)
import Data.Maybe (isNothing)

tests :: TestTree
tests =
  testGroup
    "EcdsaSecp256k1 Test Vectors"
    [
      testCase "Test vector 1 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 0),
      testCase "Test vector 2 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 1),
      testCase "Test vector 3 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 2),
      testCase "Test vector 4 - Verification should Pass when sign and verification is performed." $ signAndVerifyTestVector (signAndVerifyTestVectors !! 3),
      testCase "Test vector 5 - Verification should Pass when using given signature, vkey and message." $ verifyOnlyTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 0),
      testCase "Test vector 6 - toMessageHash should return Nothing when using invalid length message hash." $ wrongMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 0),
      testCase "Test vector 7 - toMessageHash should return Nothing when using invalid length message hash." $ wrongMessageHashLengthTestVector (wrongLengthMessageHashTestVectors !! 1),
      testCase "Test vector 8 - Verification should Fail when using wrong verification key." $ wrongVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 0),
      testCase "Test vector 9 - Verification should Fail when using verification key that is not on the curve." $ verificationKeyNotOnCurveTestVector (wrongVerificationKeyTestVectors !! 1),
      testCase "Test vector 10 - Verification should Fail when using wrong message but right signature." $ wrongMessageRightSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 0),
      testCase "Test vector 11 - Verification should Fail when using right message but wrong signature." $ rightMessageWrongSignatureTestVector (wrongMessagesAndSignaturesTestVectors !! 1),
      testCase "Test vector 12 - Verification should Fail when using invalid length verification key." $ invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 2),
      testCase "Test vector 13 - Verification should Fail when using invalid length verification key." $ invalidLengthVerificationKeyTestVector (wrongVerificationKeyTestVectors !! 3),
      testCase "Test vector 14 - Verification should Fail when using invalid length signature." $ invalidLengthSignatureTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 1),
      testCase "Test vector 15 - Verification should Fail when using invalid length signature." $ invalidLengthSignatureTestVector (ecdsa256k1VKeyAndSigVerifyTestVectors !! 2)
    ]

--Whole sign and verify flow test vector
signAndVerifyTestVector :: (String, String, String) -> IO ()
signAndVerifyTestVector (sKey, vKey, msg) = do
  result <- ecdsaSignAndVerifyTestVector sKey vKey msg
  assertBool "Test failed. Sign and verification should be successful." $ isRight result

-- Parse exsiting signature and verify using vkey msg and signature only
verifyOnlyTestVector :: (String, String, String, String) -> IO ()
verifyOnlyTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr
  assertBool "Test failed. Sign and verification should be successful." $ isRight result

-- Pass invalid length message hash in signing stage
wrongMessageHashLengthTestVector :: String -> IO ()
wrongMessageHashLengthTestVector msg = do
  let msgHash = toMessageHash $ BSU.fromString msg
  assertBool "Test failed. Wrong message hash length is treated as right." $ isNothing msgHash

-- Use another verification to verify the message sign by another sign key
wrongVerificationKeyTestVector :: String -> IO ()
wrongVerificationKeyTestVector wrongVKey = do
  result <- ecdsaSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage
  assertBool "Test failed. Verification successful on using wrong verification key." $ isLeft result

-- Sign using one message but verify using another message but right signature
wrongMessageRightSignatureTestVector :: (String, String, String) -> IO ()
wrongMessageRightSignatureTestVector (signMsg, verifyMsg, _) = do
  result <- ecdsaSignAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing Nothing
  assertBool "Test failed. Verification successful on using wrong message." $ isLeft result

-- Sign using one message and verify using same message but wrong signature
rightMessageWrongSignatureTestVector :: (String, String, String) -> IO ()
rightMessageWrongSignatureTestVector (signMsg, verifyMsg, signature) = do
  result <- ecdsaSignAndVerify defaultSKey defaultVKey (Just signMsg) (Just verifyMsg) Nothing Nothing (Just signature)
  assertBool "Test failed. Verification successful on using wrong signature." $ isLeft result

-- Use invalid verification key length and try to verify using vkey msg and signature only
invalidLengthVerificationKeyTestVector :: String -> IO ()
invalidLengthVerificationKeyTestVector invalidVKey = do
  result <- try (verifyOnlyWithSigTestVector defaultSKey invalidVKey defaultMessage defaultEcdsaSignature) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using wrong verification key length." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertEqual "Expected wrong length error." (invalidEcdsaVerificationKeyLengthError invalidVKey) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length verification key should not be successful."

-- Parse exsiting invalid signature and try to verify using vkey msg and signature only
invalidLengthSignatureTestVector :: (String, String, String, String) -> IO ()
invalidLengthSignatureTestVector (sKeyStr, vKeyStr, msg, sigStr) = do
  result <- try (verifyOnlyWithSigTestVector sKeyStr vKeyStr msg sigStr) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using wrong signature length." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertEqual "Expected wrong length error." (invalidEcdsaSignatureLengthError sigStr) err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using invalid length signature should not be successful."

-- Use verification key that is not on the curve
verificationKeyNotOnCurveTestVector :: String -> IO ()
verificationKeyNotOnCurveTestVector wrongVKey = do
  result <- try (ecdsaSignAndVerifyTestVector defaultSKey wrongVKey defaultMessage) :: IO (Either DecoderError SignatureResult)
  assertBool "Test failed. Verification successful on using verification key not on the curve." $ isLeft result
  case result of
    Left (DecoderErrorDeserialiseFailure _ (DeserialiseFailure _ err)) -> do
      assertEqual "Expected cannot decode key error." cannotDecodeVerificationKeyError err
    Left _ -> error unexpectedDecodingError
    Right _ -> error "Test failed. Sign and verified when using verification not on the curve should not be successful."

-- Simple sign and verify test vector function with sKey, vKey and message in string
ecdsaSignAndVerifyTestVector :: String -> String -> String -> IO SignatureResult
ecdsaSignAndVerifyTestVector sKeyStr vKeyStr signMsg = ecdsaSignAndVerify sKeyStr vKeyStr (Just signMsg) (Just signMsg) Nothing Nothing Nothing

-- Simple verify only test vector with verification message and signature in string
verifyOnlyWithSigTestVector :: String -> String -> String -> String -> IO SignatureResult
verifyOnlyWithSigTestVector sKeyStr vKeyStr verifyMsg sig = ecdsaSignAndVerify sKeyStr vKeyStr Nothing (Just verifyMsg) Nothing Nothing (Just sig)

signMessageHashNotPresent :: String
signMessageHashNotPresent = "Sign Message or message hash must be present. Encountered both Nothing."

verifyMessageHashNotPresent :: String
verifyMessageHashNotPresent = "Sign Message or message hash must be present. Encountered both Nothing."

-- Sign and verify flow with optional message hash for sign and verify, optional signature and use them appropriately for sign and verify
ecdsaSignAndVerify :: String -> String -> Maybe String -> Maybe String -> Maybe MessageHash -> Maybe MessageHash -> Maybe String -> IO SignatureResult
ecdsaSignAndVerify sKeyStr vKeyStr signMsgM verifyMsgM signHashM verifyHashM sigM = do
  let signMh = case (signMsgM, signHashM) of
        (_, Just msgHash) -> msgHash
        (Just signMsg, Nothing) -> hashMessage signMsg
        (Nothing, Nothing) -> error signMessageHashNotPresent
  let verifyMh = case (verifyMsgM, verifyHashM) of
        (_, Just msgHash) -> msgHash
        (Just verifyMsg, Nothing) -> hashMessage verifyMsg
        (Nothing, Nothing) -> error verifyMessageHashNotPresent
  sig <- case sigM of
    Just sig' -> parseEcdsaSignature sig'
    Nothing -> ecdsaSign sKeyStr signMh
  ecdsaVerify vKeyStr verifyMh sig

-- Sign the message hash by parsing the sign key in string
ecdsaSign :: String -> MessageHash -> IO (SigDSIGN EcdsaSecp256k1DSIGN)
ecdsaSign sKeyStr mh = do
  sKey <- parseEcdsaSignKey sKeyStr
  pure $ signDSIGN () mh sKey

-- Verify using vKey in string parse it, use message hash and ecdsa signature
-- to verify it and return results
ecdsaVerify :: String -> MessageHash -> SigDSIGN EcdsaSecp256k1DSIGN -> IO SignatureResult
ecdsaVerify vKeyStr mh sig = do
  vKey <- parseEcdsaVerKey vKeyStr
  pure $ verifyDSIGN () vKey mh sig

--Hash message using SHA3_256
hashMessage :: String -> MessageHash
hashMessage msg = hashAndPack (Proxy @SHA3_256) $ BSU.fromString msg

-- Convert vKeyInHex to appropirate vKey
parseEcdsaVerKey :: String -> IO (VerKeyDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaVerKey vKeyHex = do
  vKeyBytes <- convertToBytes vKeyHex
  let vKeyE = decodeFull' vKeyBytes
  case vKeyE of
    Left err -> throw err
    Right vKey -> pure vKey

-- Convert sKeyInHex to appropirate sKey
parseEcdsaSignKey :: String -> IO (SignKeyDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaSignKey sKeyHex = do
  sKeyBytes <- convertToBytes sKeyHex
  let sKeyE = decodeFull' sKeyBytes
  case sKeyE of
    Left err -> throw err
    Right sKey -> pure sKey

-- Convert sigInHex to appropirate signature
parseEcdsaSignature :: String -> IO (SigDSIGN EcdsaSecp256k1DSIGN)
parseEcdsaSignature sigHex = do
  sigBytes <- convertToBytes sigHex
  let sigE = decodeFull' sigBytes :: Either DecoderError (SigDSIGN EcdsaSecp256k1DSIGN)
  case sigE of
    Left err -> throw err
    Right sig -> pure sig
