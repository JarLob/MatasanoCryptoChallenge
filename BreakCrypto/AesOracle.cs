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
    }
}
