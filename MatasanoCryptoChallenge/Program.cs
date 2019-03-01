using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace MatasanoCryptoChallenge
{
    class Program
    {
        static void Main(string[] args)
        {
        }
    }

    public static class Hex
    {
        public static byte[] ToBytes(string hex)
        {
            var bytes = Enumerable.Range(0, hex.Length)
                                  .Where(x => x % 2 == 0)
                                  .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                                  .ToArray();

            return bytes;
        }

        public static string ToString(byte[] data)
        {
            var output = new StringBuilder(data.Length*2);

            foreach (var b in data)
            {
                output.AppendFormat("{0:x2}", b);
            }

            return output.ToString();
        }
    }

    public static class PKCS7
    {
        public static byte[] Pad(ArraySegment<byte> data, byte blockSize)
        {
            byte mod = (byte)(data.Count % blockSize);
            byte padSize = mod == 0 ? blockSize : (byte)(blockSize - mod);
            var output = new byte[data.Count + padSize];
            data.CopyTo(output, 0);

            for (int i = data.Count; i < output.Length; ++i)
            {
                output[i] = padSize;
            }
            return output;
        }

        public static Span<byte> StripPad(Span<byte> data)
        {
            return data.Slice(0, data.Length - data[data.Length - 1]);
        }
    }

    public static class MyAes
    {
        public static byte[] Decrypt(byte[] cipher, byte[] key, CipherMode mode)
        {
            if (mode != CipherMode.ECB)
                throw new NotImplementedException();

            return DecryptEcb(cipher, key);
        }

        public static byte[] Encrypt(byte[] data, byte[] key, CipherMode mode)
        {
            if (mode == CipherMode.ECB)
            {
                return EncryptEcb(data, key);
            }
            else if (mode == CipherMode.CBC)
            {
                var len = data.Length / 16 + 1;
                var output = new byte[len * 16];
                var prevBlock = new byte[16];
                int i = 0;
                for (; i < len - 1; i++)
                {
                    var xored = Xor.ApplyFixed(prevBlock, data.AsSpan(i * 16, 16));
                    var encrypted = EncryptEcb(xored, key, PaddingMode.None);
                    Array.Copy(encrypted, 0, output, i * 16, 16);
                    prevBlock = encrypted;
                }

                var padded = PKCS7.Pad(new ArraySegment<byte>(data, i * 16, data.Length % 16), 16);
                Array.Copy(EncryptEcb(Xor.ApplyFixed(prevBlock, padded), key), 0, output, i * 16, 16);
                return output;
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        public static byte[] PaddingEncrypt(RandomNumberGenerator rnd, byte[] key, ArraySegment<byte> plainText, byte[] after)
        {
            var appended = new byte[plainText.Count + after.Length];
            plainText.CopyTo(appended);
            Array.Copy(after, 0, appended, plainText.Count, after.Length);
            return Encrypt(appended, key, CipherMode.ECB);
        }

        private static byte[] DecryptEcb(byte[] cipher, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key  = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = padding;

                using (var decr = aes.CreateDecryptor())
                {
                    var text = decr.TransformFinalBlock(cipher, 0, cipher.Length);
                    return text;
                }
            }
        }

        private static byte[] EncryptEcb(byte[] data, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key  = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = padding;

                using (var encr = aes.CreateEncryptor())
                {
                    var text = encr.TransformFinalBlock(data, 0, data.Length);
                    return text;
                }
            }
        }
    }

    public static class Hamming
    {
        public static uint GetDistance(ReadOnlySpan<byte> xArray, ReadOnlySpan<byte> yArray)
        {
            if (xArray.Length != yArray.Length)
                throw new Exception();

            uint count = 0;
            int i = 0;

            unsafe
            {
                fixed (byte* pX = xArray, pY = yArray)
                {
                    for (; i + sizeof(ulong) < xArray.Length; i += sizeof(ulong))
                    {
                        var diff = *(ulong*)&pX[i] ^ *(ulong*)&pY[i];
                        count += BitCount(diff);
                    }

                    for (; i + sizeof(uint) < xArray.Length; i += sizeof(uint))
                    {
                        var diff = *(uint*)&pX[i] ^ *(uint*)&pY[i];
                        count += BitCount(diff);
                    }
                }
            }

            for (; i < xArray.Length; ++i)
            {
                var diff = (byte)(xArray[i] ^ yArray[i]);
                count += BitCount(diff);
            }

            return count;
        }

        public static byte BitCount(ulong value)
        {
            var result = value - ((value >> 1) & 0x5555555555555555UL);
            result = (result & 0x3333333333333333UL) + ((result >> 2) & 0x3333333333333333UL);
            return (byte)(unchecked(((result + (result >> 4)) & 0xF0F0F0F0F0F0F0FUL) * 0x101010101010101UL) >> 56);
        }

        public static byte BitCount(uint value)
        {
            var result = value - ((value >> 1) & 0x55555555);
            result = (result & 0x33333333) + ((result >> 2) & 0x33333333);
            return (byte)(unchecked(((result + (result >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24);
        }

        public static byte BitCount(byte value)
        {
            byte count = 0;
            for (; value != 0; ++count)
            {
                value &= (byte)(value - 1);
            }

            return count;
        }
    }

    public static class Xor
    {
        public static byte[] ApplyFixed(byte[] bytesData, ReadOnlySpan<byte> bytesKey)
        {
            if (bytesData.Length != bytesKey.Length)
                throw new Exception();

            var output = new byte[bytesData.Length];
            for (var i = 0; i < bytesData.Length; i++)
            {
                output[i] = (byte)(bytesData[i] ^ bytesKey[i]);
            }

            return output;
        }

        public static byte[] ApplyRepeating(byte[] bytesData, byte[] bytesKey)
        {
            int k = 0;
            var output = new byte[bytesData.Length];
            for (var i = 0; i < bytesData.Length; i++)
            {
                output[i] = (byte)(bytesData[i] ^ bytesKey[k]);
                if (++k == bytesKey.Length)
                    k = 0;
            }

            return output;
        }

        private static readonly Dictionary<char, double> EnglishFreq = new Dictionary<char, double>()
        {
            // From http://www.data-compression.com/english.html
            {'a', 0.0651738},
            {'b', 0.0124248},
            {'c', 0.0217339},
            {'d', 0.0349835},
            {'e', 0.1041442},
            {'f', 0.0197881},
            {'g', 0.0158610},
            {'h', 0.0492888},
            {'i', 0.0558094},
            {'j', 0.0009033},
            {'k', 0.0050529},
            {'l', 0.0331490},
            {'m', 0.0202124},
            {'n', 0.0564513},
            {'o', 0.0596302},
            {'p', 0.0137645},
            {'q', 0.0008606},
            {'r', 0.0497563},
            {'s', 0.0515760},
            {'t', 0.0729357},
            {'u', 0.0225134},
            {'v', 0.0082903},
            {'w', 0.0171272},
            {'x', 0.0013692},
            {'y', 0.0145984},
            {'z', 0.0007836},
            {' ', 0.1918182}
        };

        public static (string plainText, byte key, double score) XorBestMatch(byte[] xoredBytes)
        {
            var candidate = (plainText: default(string), key: default(byte), score: 0.0);
            byte[] key = new byte[1];
            for (int i = 0; i < 256; ++i)
            {
                key[0] = (byte)i;
                var plainText = Encoding.UTF8.GetString(Xor.ApplyRepeating(xoredBytes, key));
                var lowerCaseText = plainText.ToLowerInvariant();

                double score = 0.0;
                foreach (var c in lowerCaseText)
                {
                    if (EnglishFreq.TryGetValue(c, out var sc))
                        score += sc;
                }

                if (score > candidate.score && Math.Abs(score - candidate.score) > 0.001)
                {
                    candidate.score = score;
                    candidate.key = key[0];
                    candidate.plainText = plainText;
                }
            }

            return candidate;
        }
    }

    public static class CryptoRandom
    {
        public static int GetInt(this RandomNumberGenerator rng)
        {
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            return BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF;
        }

        public static int GetInt(this RandomNumberGenerator rng, int maxValue)
        {
            if (maxValue < 0)
                throw new ArgumentOutOfRangeException("maxValue");

            return GetInt(rng, 0, maxValue);
        }

        public static int GetInt(this RandomNumberGenerator rng, int minValue, int maxValue)
        {
            if (minValue > maxValue)
                throw new ArgumentOutOfRangeException("minValue");

            if (minValue == maxValue)
                return minValue;

            long diff = maxValue - minValue + 1;
            var bytes = new byte[4];

            long max       = (1 + (long)UInt32.MaxValue);
            long remainder = max % diff;

            while (true)
            {
                rng.GetBytes(bytes);
                var rand = BitConverter.ToUInt32(bytes, 0);

                if (rand < max - remainder)
                {
                    return (Int32)(minValue + (rand % diff));
                }
            }
        }

        public static double GetDouble(this RandomNumberGenerator rng)
        {
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var rand = BitConverter.ToUInt32(bytes, 0);
            return rand / (1.0 + UInt32.MaxValue);
        }
    }

    public static class AesOracle
    {
        public static CipherMode GuessMode(byte[] encrypted, int blockSize)
        {
            for (int x = 0; x < encrypted.Length / blockSize; ++x)
            {
                for (int y = x + 1; y < encrypted.Length / blockSize; ++y)
                {
                    if (AreBlocksEqual(encrypted.AsSpan(x * blockSize, blockSize), encrypted.AsSpan(y * blockSize, blockSize)))
                    {
                        return CipherMode.ECB;
                    }
                }
            }

            return CipherMode.CBC;
        }

        public static int GuessBlockSize(Func<ArraySegment<byte>, byte[]> encrypt)
        {
            var payload = new byte[100];
            int blockSize = 1;
            int changedSize = 0;
            int encryptedSize = 0;
            for (; blockSize < payload.Length; ++blockSize)
            {
                var encrypted = encrypt(new ArraySegment<byte>(payload, 0, blockSize));
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

            return -1;
        }

        public static Span<byte> ByteAtATimeEcb(int blockSize, Func<ArraySegment<byte>, byte[]> encrypt)
        {
            var encrypted = encrypt(new byte[0]);
            var secretLength = encrypted.Length;

            var buffer = new byte[secretLength + blockSize - 1];
            for (int j = 0; j < buffer.Length; ++j)
                buffer[j] = (byte)'A';

            var cipherTexts = new byte[blockSize][];
            cipherTexts[blockSize - 1] = encrypted;

            for (int j = 0; j < blockSize - 1; ++j)
            {
                cipherTexts[j] = encrypt(new ArraySegment<byte>(buffer, 0, blockSize - 1 - j));
            }

            int i;
            for (i = 0; i < secretLength; ++i)
            {
                int guessedByte;
                for (guessedByte = 0; guessedByte < 256; ++guessedByte)
                {
                    buffer[blockSize - 1 + i] = (byte)guessedByte;
                    if (AreBlocksEqual(cipherTexts[i % blockSize].AsSpan(i / blockSize * blockSize, blockSize),
                                       encrypt(new ArraySegment<byte>(buffer, i, blockSize)).AsSpan(0, blockSize)))
                    {
                        break;
                    }
                }

                if (guessedByte == 256)
                    break;
            }

            return PKCS7.StripPad(buffer.AsSpan(blockSize - 1, i));
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

    public static class RandomEncryptor
    {
        public static (byte[] cipher, CipherMode mode) Encrypt(byte[] plainText)
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                var before = new byte[rnd.GetInt(5, 10)];
                rnd.GetBytes(before);

                var after = new byte[rnd.GetInt(5, 10)];
                rnd.GetBytes(after);

                var appended = new byte[before.Length + plainText.Length + after.Length];
                Array.Copy(before, appended, before.Length);
                Array.Copy(plainText, 0, appended, before.Length, plainText.Length);
                Array.Copy(after, 0, appended, before.Length + plainText.Length, after.Length);

                var m = rnd.GetInt(0, 1);
                var mode = m % 2 == 0 ? CipherMode.CBC : CipherMode.ECB;
                return (MyAes.Encrypt(appended, key, mode), mode);
            }
        }
    }
}
