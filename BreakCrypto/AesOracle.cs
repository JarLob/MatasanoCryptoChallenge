using System;
using System.Security.Cryptography;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class AesOracle
    {
        // ECB always produces same output from the same input
        // If we find two blocks that are the same, it is ECB
        public static CipherMode GuessMode(ReadOnlySpan<byte> encrypted, int blockSize)
        {
            for (int x = 0; x < encrypted.Length / blockSize; ++x)
            {
                for (int y = x + 1; y < encrypted.Length / blockSize; ++y)
                {
                    if (AreBlocksEqual(encrypted.Slice(x * blockSize, blockSize), encrypted.Slice(y * blockSize, blockSize)))
                    {
                        return CipherMode.ECB;
                    }
                }
            }

            return CipherMode.CBC;
        }

        // The encryted data size is grown in block size steps
        // Increase the input and detect the first encrypted data increase, it is the block size
        public static int GuessBlockSize(Func<ReadOnlySpan<byte>, byte[]> encryptionOracle)
        {
            var payload = new byte[100];
            int blockSize = 1;
            int changedSize = 0;
            int encryptedSize = 0;
            for (; blockSize < payload.Length; ++blockSize)
            {
                var encrypted = encryptionOracle(payload.AsSpan(0, blockSize));
                if (encryptedSize != encrypted.Length)
                {
                    ++changedSize;
                    if (changedSize == 2)
                    {
                        return encrypted.Length - encryptedSize;
                    }

                    encryptedSize = encrypted.Length;
                }
            }

            throw new Exception();
        }

        public static int GetPrefixLength(int blockSize, Func<ReadOnlySpan<byte>, byte[]> encryptionOracle)
        {
            var payload = new byte[blockSize + 1];

            // |unknown unknown |unknown 00000000|000000000padding|
            var encrypted1 = encryptionOracle(payload);
            payload[0] = 1;
            // |unknown unknown |unknown 10000000|000000000padding|
            var encrypted2 = encryptionOracle(payload);
            var blockNr = GetFirstDifferentBlock(encrypted1, encrypted2, blockSize);

            for (int i = 1; i < payload.Length; ++i)
            {
                payload[i - 1] = 0;
                payload[i] = 1;
                // |unknown unknown |unknown 01000000|000000000padding|
                // |unknown unknown |unknown 00100000|000000000padding|
                // |unknown unknown |unknown 00010000|000000000padding|
                // etc
                // |unknown unknown |unknown 00000000|100000000padding|
                encrypted2 = encryptionOracle(payload);
                if (GetFirstDifferentBlock(encrypted1, encrypted2, blockSize) != blockNr)
                    return blockSize * blockNr + (blockSize - i);
            }

            throw new Exception();
        }

        private static int GetFirstDifferentBlock(ReadOnlySpan<byte> array1, ReadOnlySpan<byte> array2, int blockSize)
        {
            if (array1.Length != array2.Length)
                throw new Exception();

            int blockNr;
            for (blockNr = 0; blockNr < array1.Length / blockSize; ++blockNr)
            {
                if (!AreBlocksEqual(array1.Slice(blockNr * blockSize, blockSize), array2.Slice(blockNr * blockSize, blockSize)))
                    return blockNr;
            }

            throw new Exception();
        }

        public static ReadOnlySpan<byte> SuffixByteAtATime(int blockSize, int prefixLength,
                                                           Func<ReadOnlySpan<byte>, byte[]> encryptionOracle)
        {
            if (prefixLength < 0)
                throw new Exception();

            // detect suffix length
            var suffixLength = encryptionOracle(ReadOnlySpan<byte>.Empty).Length - prefixLength;
            for (int s = 1; s <= blockSize; ++s)
            {
                var encryptedLen = encryptionOracle(new byte[s]).Length - prefixLength;
                if (encryptedLen != suffixLength)
                {
                    suffixLength = encryptedLen - blockSize - s;
                    break;
                }
            }
            var prefixPaddingLength = prefixLength > 0 ? blockSize - (prefixLength % blockSize) : 0;

            var buffer = new byte[prefixPaddingLength + blockSize - 1 + suffixLength];
            var cipherTexts = new byte[blockSize][];

            // build cipher texts with:
            // prefix...padding|000000000000000u|nknownsuffix....|continues...... -> ndkwlrixmrvuqntv|oqlxgevzirnvarpx|ywbamrbqcoenzybr
            // prefix...padding|00000000000000un|knownsuffix....c|ontinues......
            // prefix...padding|0000000000000unk|nownsuffix....co|ntinues......
            // prefix...padding|000000000000unkn|ownsuffix....con|tinues......
            // etc
            // prefix...padding|unknownsuffix...|.continues......|
            for (int j = 0; j < blockSize; ++j)
            {
                cipherTexts[j] = encryptionOracle(buffer.AsSpan(0, prefixPaddingLength + blockSize - 1 - j));
            }

            int i;
            for (i = 0; i < suffixLength; ++i)
            {
                // For i == 0 take the encrypted part of the first block of the first element in cipherTexts (but skip prefix blocks),
                // i.e. |000000000000000u| where 'u' is the first character for unknown suffix
                // for i == 1 take the encrypted part of the first block of the _second_ element in cipherTexts,
                // i.e. | 00000000000000un | where "un" are the first two characters for unknown suffix
                // for i == 16 take the encrypted part of |nknownsuffix....| - the second block of the first item in the dictionary
                // for i == 17 take the encrypted part of |knownsuffix....c| - the second block of the second item in the dictionary
                // etc.
                var dictionaryBlock = cipherTexts[i % blockSize].AsSpan(prefixLength + prefixPaddingLength + i / blockSize * blockSize, blockSize);

                int guessedByte;
                for (guessedByte = 255; guessedByte >= 0; --guessedByte)
                {
                    buffer[prefixPaddingLength + blockSize - 1 + i] = (byte)guessedByte;

                    // The guessed input block is always block size and
                    // the span window is moving byte by byte to the right,
                    // up to the block size and then again from the beginning of the block:
                    // prefix...padding|000000000000000X|nknownsuffix....|continues
                    //                  ^
                    // where X is the guessed byte
                    // then
                    // prefix...padding|000000000000000u|Xknownsuffix....|continues -> padding|00000000000000uX|knownsuffix....c|ontinues
                    //                   ^
                    // so the input becomes padding|00000000000000uX|
                    // where 'u' is already found byte
                    // etc. i.e. i == 23
                    // prefix...padding|000000000000000u|nknownXuffix....|continues -> padding|00000000unknownX|uffix....contin|ues
                    //                         ^
                    // so the input becomes padding|000000000unknown|suffix....contiX|
                    // where 'unknown' are already found bytes
                    var block2 = encryptionOracle(buffer.AsSpan(i % blockSize,
                                                                prefixPaddingLength + i / blockSize * blockSize + blockSize))
                        .AsSpan(prefixLength + prefixPaddingLength + i / blockSize * blockSize, blockSize);
                    if (AreBlocksEqual(dictionaryBlock, block2))
                    {
                        break;
                    }
                }

                if (guessedByte == -1)
                    throw new Exception("Unexpected: the byte wasn't found");
            }

            return buffer.AsSpan(prefixPaddingLength + blockSize - 1, i);
        }

        private static bool AreBlocksEqual(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y)
        {
            if (x.Length != y.Length)
                throw new Exception();

            for (int i = 0; i < x.Length; ++i)
            {
                if (x[i] != y[i])
                    return false;
            }

            return true;
        }

        public static ReadOnlySpan<byte> PaddingDecryptCBC(ReadOnlySpan<byte> encrypted,
                                                           Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>, bool> validateOracle,
                                                           ReadOnlySpan<byte> iv = default)
        {
            if (encrypted.Length % 16 != 0)
                throw new Exception();

            var decrypted = new byte[encrypted.Length];
            Span<byte> fakeEncrypted = new byte[16 * 2];

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block >= 0; --block)
            {
                ReadOnlySpan<byte> realPrevBlock;
                if (block == 0)
                    realPrevBlock = iv.IsEmpty ? new byte[16] : iv;
                else
                    realPrevBlock = encrypted.Slice((block - 1) * 16, 16);

                Span<byte> fakePrevBlock = new byte[16];
                for (int i = 15; i >= 0; --i)
                {
                    realPrevBlock.CopyTo(fakePrevBlock);
                    byte desiredPaddingValue = (byte)(16 - i);

                    // set bytes past the current index to produce needed padding as
                    // "0x02" or "0x03 0x03" or "0x04 0x04 0x04" etc.
                    // by using already decrypted values
                    for (int n = 15; n > i; --n)
                    {
                        fakePrevBlock[n] = (byte)(realPrevBlock[n] ^ decrypted[block * 16 + n] ^ desiredPaddingValue);
                    }

                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("Unexpected: the byte wasn't found");

                        fakePrevBlock[i] = (byte)b;
                        fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                        encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                        if (validateOracle(fakeEncrypted, iv))
                        {
                            // once we have decrypted the last byte and desiredPaddingValue != 1 we force the padding value above
                            // so we don't need the check
                            if (i != 0 && desiredPaddingValue == 1)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02" or "0x03 0x03 0x03" or etc.
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                fakePrevBlock[i - 1] += 1;
                                fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                                encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                                if (!validateOracle(fakeEncrypted, iv))
                                    continue;
                            }

                            // At this point we know that b XOR D(encrypted) = desiredPaddingValue
                            // However the real plaintext = realPrevBlock[i] XOR D(encrypted)
                            // From two equations above: D(encrypted) = desiredPaddingValue XOR b = plaintext XOR realPrevBlock[i]
                            decrypted[block * 16 + i] = (byte)(b ^ desiredPaddingValue ^ realPrevBlock[i]);
                            break;
                        }
                    }
                }
            }

            return PKCS7.StripPad(decrypted);
        }

        public static ReadOnlySpan<byte> PaddingEncryptCBC(ReadOnlySpan<byte> payload,
                                                           Func<ReadOnlySpan<byte>, bool> validateOracle)
        {
            ReadOnlySpan<byte> payloadPadded = PKCS7.Pad(payload, 16).AsSpan();
            var encrypted = new byte[16 + payloadPadded.Length];

            using (var rnd = RandomNumberGenerator.Create())
            {
                // the last block is of our choice and could be constant
                // but since we don't know the IV and produce a garbage block
                // the decrypted value may cause parsing errors
                // it is better to randomize it every time
                rnd.GetBytes(encrypted.AsSpan(encrypted.Length - 16));
            }

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block > 0; --block)
            {
                for (int i = 15; i >= 0; --i)
                {
                    byte desiredPaddingValue = (byte)(16 - i);
                    var twoBlocks = encrypted.AsSpan((block - 1) * 16, 32);
                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("Unexpected: the byte wasn't found");

                        twoBlocks[i] = (byte)b;
                        if (validateOracle(twoBlocks))
                        {
                            if (i != 0 && desiredPaddingValue == 1)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02" or "0x03 0x03 0x03" or etc.
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                twoBlocks[i - 1] += 1;
                                if (!validateOracle(twoBlocks))
                                    continue;
                            }

                            for (int j = 15; j >= i; --j)
                            {
                                // We know that the decrypted and xored value is of valid padding
                                // Xor it again with the padding value to calculate values that produce Zeroes instead of the padding
                                // Zeros will be conveniet later for xoring with the payload
                                twoBlocks[j] = (byte)(twoBlocks[j] ^ desiredPaddingValue);
                                if (desiredPaddingValue < 16)
                                    // calculate values for the next round: Xor it again with the next padding value
                                    twoBlocks[j] = (byte)(twoBlocks[j] ^ (desiredPaddingValue + 1));
                            }
                            break;
                        }
                    }
                }

                var c = encrypted.AsSpan((block - 1) * 16, 16);
                var p = payloadPadded.Slice((block - 1) * 16, 16);
                for (int j = 15; j >= 0; --j)
                    // The calculated values in the block will produce zeroes when xored with the next decrypted block
                    // Just xor them with desiried payload
                    c[j] = (byte)(c[j] ^ p[j]);
            }

            return encrypted;
        }
    }
}
