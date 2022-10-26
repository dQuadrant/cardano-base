{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Test.Crypto.Vector.VectorUtil
  ( toHex,
    unHex,
    byteStringToString,
    toHexByteString,
    convertToBytes,
    hexLength,
    unsafeUnHex,
    SignatureResult,
    HexString (..),
    sKeyParser,
    vKeyParser,
    sigParser,
    drop,
    stringToByteString,
  )
where

import Cardano.Binary (FromCBOR, ToCBOR, serialize', unsafeDeserialize')
import Cardano.Crypto.DSIGN
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as BS16
import qualified Data.ByteString.UTF8 as BSU -- from utf8-string
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Numeric (showHex)
import Prelude hiding (drop)
import qualified Prelude

defaultCborPrefix :: String
defaultCborPrefix = "58"

-- Convert raw bytes to base16
toHex :: ToCBOR a => a -> Int -> String
toHex a dropFront = T.unpack $ T.decodeUtf8 $ BS.drop dropFront $ BS16.encode $ serialize' a

--Convert bas16 to raw bytes
unHex :: ByteString -> Either String ByteString
unHex = BS16.decode

unsafeUnHex :: ByteString -> ByteString
unsafeUnHex hexBs = case unHex hexBs of
  Left _ -> error "Error: Couldn't unHex the Hex string. Incorrect format."
  Right bytes' -> bytes'

-- Convert byteString to String
byteStringToString :: ByteString -> String
byteStringToString = T.unpack . T.decodeUtf8

toHexByteString :: ByteString -> ByteString
toHexByteString = BS16.encode

convertToBytes :: String -> ByteString
convertToBytes hexStr =
  let bytesLengthHex = showHex (hexLength hexStr) ""
      hexBs = BSU.fromString $ defaultCborPrefix ++ bytesLengthHex ++ hexStr
   in unsafeUnHex hexBs

hexLength :: String -> Int
hexLength hexStr = length hexStr `div` 2

type SignatureResult = (Either String ())

sKeyParser :: forall d. (FromCBOR (SignKeyDSIGN d)) => String -> SignKeyDSIGN d
sKeyParser = unsafeDeserialize' . convertToBytes

vKeyParser :: forall d. (FromCBOR (VerKeyDSIGN d)) => String -> VerKeyDSIGN d
vKeyParser = unsafeDeserialize' . convertToBytes

sigParser :: forall d. (FromCBOR (SigDSIGN d)) => String -> SigDSIGN d
sigParser = unsafeDeserialize' . convertToBytes

stringToByteString :: String -> ByteString
stringToByteString = BSU.fromString

-- Wrapper for String containing Hex values
newtype HexString = HexString String

drop :: Int -> HexString -> HexString
drop n (HexString hs) = HexString $ Prelude.drop n hs
