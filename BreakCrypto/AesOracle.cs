using System;
using System.Security.Cryptography;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class AesOracle
    {
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

        public static int GuessBlockSize(Func<ReadOnlyMemory<byte>, byte[]> encrypt)
        {
            var payload = new byte[100];
            int blockSize = 1;
            int changedSize = 0;
            int encryptedSize = 0;
            for (; blockSize < payload.Length; ++blockSize)
            {
                var encrypted = encrypt(new ReadOnlyMemory<byte>(payload, 0, blockSize));
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

        public static int GetPrefixLength(int blockSize, Func<ReadOnlyMemory<byte>, byte[]> encrypt)
        {
            var payload = new byte[blockSize + 1];

            var encrypted1 = encrypt(payload);
            payload[0] = 1;
            var encrypted2 = encrypt(payload);
            var blockNr = GetFirstDifferentBlock(encrypted1, encrypted2, blockSize);

            for (int i = 1; i < payload.Length; ++i)
            {
                payload[i - 1] = 0;
                payload[i] = 1;
                encrypted2 = encrypt(payload);
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

        public static ReadOnlySpan<byte> ByteAtATimeEcb(int blockSize, Func<ReadOnlyMemory<byte>, byte[]> encrypt, int prefixLength = 0)
        {
            if (prefixLength < 0)
                throw new Exception();

            var encrypted = encrypt(new byte[0]);
            var suffixLength = encrypted.Length - prefixLength;
            var prefixPaddingLength = prefixLength > 0 ? blockSize - (prefixLength % blockSize) : 0;

            var buffer = new byte[prefixPaddingLength + blockSize - 1 + suffixLength];
            var cipherTexts = new byte[blockSize][];

            for (int j = 0; j < blockSize; ++j)
            {
                cipherTexts[j] = encrypt(new ReadOnlyMemory<byte>(buffer, 0, prefixPaddingLength + blockSize - 1 - j));
            }

            int i;
            for (i = 0; i < buffer.Length - prefixPaddingLength - blockSize + 1; ++i)
            {
                int guessedByte;
                for (guessedByte = 255; guessedByte >= 0; --guessedByte)
                {
                    buffer[prefixPaddingLength + blockSize - 1 + i] = (byte)guessedByte;
                    if (AreBlocksEqual(cipherTexts[i % blockSize].AsSpan(prefixLength + prefixPaddingLength + i / blockSize * blockSize, blockSize),
                                       encrypt(new ReadOnlyMemory<byte>(buffer, i, prefixPaddingLength + blockSize)).AsSpan(prefixLength + prefixPaddingLength, blockSize)))
                    {
                        break;
                    }
                }

                if (guessedByte == -1)
                    break;
            }

            return PKCS7.StripPad(buffer.AsSpan(prefixPaddingLength + blockSize - 1, i));
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
