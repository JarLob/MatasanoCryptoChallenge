using System;
using System.Collections.Generic;
using System.IO;
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
        public static byte[] Pad(ReadOnlySpan<byte> data, byte blockSize)
        {
            byte mod = (byte)(data.Length % blockSize);
            byte padSize = mod == 0 ? blockSize : (byte)(blockSize - mod);
            var output = new byte[data.Length + padSize];
            data.CopyTo(output);

            for (int i = data.Length; i < output.Length; ++i)
            {
                output[i] = padSize;
            }
            return output;
        }

        public static ReadOnlySpan<byte> StripPad(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
                throw new Exception();

            var pads = data[data.Length - 1];
            if (pads < 1 || pads > data.Length)
                throw new CryptographicException("Padding is invalid and cannot be removed.");

            for (int i = 1; i < pads; ++i)
            {
                if (data[data.Length - i - 1] != pads)
                    throw new CryptographicException("Padding is invalid and cannot be removed.");
            }

            return data.Slice(0, data.Length - pads);
        }
    }

    public static class MyAes
    {
        public static byte[] EncryptDecryptCtr(ReadOnlySpan<byte> data, ulong nonce, byte[] key)
        {
            var nonceBytes = BitConverter.GetBytes(nonce);
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(nonceBytes);

            var blocks = data.Length / 16 + (data.Length % 16 > 0 ? 1 : 0);
            var output = new byte[data.Length];
            var nonceAndCounter = new byte[16];
            nonceBytes.CopyTo(nonceAndCounter, 0);

            for (int i = 0; i < blocks; ++i)
            {
                var counterBytes = BitConverter.GetBytes((ulong)i);
                if (!BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes);

                counterBytes.CopyTo(nonceAndCounter, 8);
                var decryptedBlock = EncryptEcb(nonceAndCounter, key, PaddingMode.None);

                var oMax = Math.Min(i * 16 + 16, data.Length);
                for (int o = i * 16, d = 0; o < oMax; ++o, ++d)
                {
                    output[o] = (byte)(decryptedBlock[d] ^ data[o]);
                }
            }

            return output;
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> data, ReadOnlySpan<byte> dataSuffix, byte[] key)
        {
            var appended = new byte[data.Length + dataSuffix.Length];
            data.CopyTo(appended);
            dataSuffix.CopyTo(appended.AsSpan(data.Length));
            return EncryptEcb(appended, key);
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> dataPrefix, ReadOnlySpan<byte> data, ReadOnlySpan<byte> dataSuffix, byte[] key)
        {
            var appended = new byte[dataPrefix.Length + data.Length + dataSuffix.Length];
            dataPrefix.CopyTo(appended);
            data.CopyTo(appended.AsSpan(dataPrefix.Length));
            dataSuffix.CopyTo(appended.AsSpan(dataPrefix.Length + data.Length));
            return EncryptEcb(appended, key);
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> data, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptEcb(data.ToArray(), key, padding);
        }

        public static byte[] EncryptEcb(byte[] data, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return _LibraryEncrypt(data, null, key, CipherMode.ECB, padding);
        }

        public static byte[] _LibraryEncrypt(byte[] data, byte[] iv, byte[] key, CipherMode mode, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key     = key;
                aes.Mode    = mode;
                aes.Padding = padding;

                if (aes.Mode == CipherMode.CBC)
                {
                    if (iv == default)
                        throw new Exception();

                    aes.IV = iv;
                }

                using (var encr = aes.CreateEncryptor())
                {
                    var text = encr.TransformFinalBlock(data, 0, data.Length);
                    return text;
                }
            }
        }

        public static byte[] DecryptEcb(ReadOnlySpan<byte> cipher, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return DecryptEcb(cipher.ToArray(), key, padding);
        }

        public static byte[] DecryptEcb(byte[] cipher, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return _LibraryDecrypt(cipher, null, key, CipherMode.ECB, padding);
        }

        public static byte[] EncryptCbcPkcs7(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, byte[] key)
        {
            return _CustomEncryptCbcPkcs7(data, iv, key);
        }

        public static byte[] EncryptCbcPkcs7(byte[] data, byte[] iv, byte[] key)
        {
            return _CustomEncryptCbcPkcs7(data, iv, key);
        }

        public static byte[] _CustomEncryptCbcPkcs7(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, byte[] key)
        {
            var len       = data.Length  / 16 + 1;
            var output    = new byte[len * 16];
            var prevBlock = iv;
            int i         = 0;
            for (; i < len - 1; i++)
            {
                var xored     = Xor.ApplyFixed(prevBlock, data.Slice(i * 16, 16));
                var encrypted = EncryptEcb(xored, key, PaddingMode.None);
                Array.Copy(encrypted, 0, output, i * 16, 16);
                prevBlock = encrypted;
            }

            var padded = PKCS7.Pad(data.Slice(i * 16, data.Length % 16), 16);
            Array.Copy(EncryptEcb(Xor.ApplyFixed(prevBlock, padded), key), 0, output, i * 16, 16);
            return output;
        }

        public static ReadOnlySpan<byte> DecryptCbcPkcs7(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> iv, byte[] key)
        {
            return _CustomDecryptCbcPkcs7(cipher, iv, key);
            //return _LibraryDecrypt(cipher.ToArray(), iv.ToArray(), key, CipherMode.CBC);
        }

        public static ReadOnlySpan<byte> DecryptCbcPkcs7(byte[] cipher, byte[] iv, byte[] key)
        {
            return _CustomDecryptCbcPkcs7(cipher, iv, key);
            //return _LibraryDecrypt(cipher, iv, key, CipherMode.CBC);
        }

        public static ReadOnlySpan<byte> _CustomDecryptCbcPkcs7(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> iv, byte[] key)
        {
            var blocks = cipher.Length / 16;
            var output = new byte[cipher.Length];
            for (int i = blocks - 1; i >= 0; --i)
            {
                ReadOnlySpan<byte> prevBlock;
                if (i == 0)
                    prevBlock = iv;
                else
                    prevBlock = cipher.Slice((i - 1) * 16, 16);

                var decryptedBlock = DecryptEcb(cipher.Slice(i * 16, 16), key, PaddingMode.None);
                var xored          = Xor.ApplyFixed(prevBlock, decryptedBlock);
                Array.Copy(xored, 0, output, i * 16, 16);
            }

            return PKCS7.StripPad(output);
        }

        public static byte[] _LibraryDecrypt(byte[] cipher, byte[] iv, byte[] key, CipherMode mode, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key     = key;
                aes.Mode    = mode;
                aes.Padding = padding;

                if (aes.Mode == CipherMode.CBC)
                {
                    if (iv == default)
                        throw new Exception();

                    aes.IV = iv;
                }

                using (var decr = aes.CreateDecryptor())
                {
                    var text = decr.TransformFinalBlock(cipher, 0, cipher.Length);
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
        public static byte[] ApplyFixed(ReadOnlySpan<byte> bytesData, ReadOnlySpan<byte> bytesKey)
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

        public static byte[] ApplyRepeating(ReadOnlySpan<byte> bytesData, ReadOnlySpan<byte> bytesKey)
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

        private static readonly Lazy<Dictionary<(char, char), Dictionary<char, double>>> EnglishFreq3 = new Lazy<Dictionary<(char, char), Dictionary<char, double>>>(() =>
        {
            var lines = File.ReadAllLines("ThirdOrderStatistics.txt");

            var row = lines[0].Split("||");
            if (row.Length != 2)
                throw new Exception();

            var letters = row.Last()
                             .Split('|')
                             .SkipLast(1)
                             .Select(x =>
                             {
                                 var trimmed = x.Trim();
                                 if (trimmed == "S")
                                     return ' ';

                                 if (trimmed.Length != 1)
                                     throw new Exception();

                                 return trimmed[0];
                             })
                             .ToArray();

            var dict = new Dictionary<(char, char), Dictionary<char, double>>(letters.Length * 2);

            foreach (var row2 in lines.Skip(2).SkipLast(5))
            {
                var letterToFreq = row2.Split("||");
                if (letterToFreq.Length != 2)
                    throw new Exception();

                var letterString = letterToFreq[0].Split(' ', StringSplitOptions.RemoveEmptyEntries);

                if (letterString.Length != 2 || letterString[0].Length != 1 || letterString[1].Length != 1)
                    throw new Exception();

                var letterChar1 = letterString[0] == "S" ? ' ' : letterString[0][0];
                var letterChar2 = letterString[1] == "S" ? ' ' : letterString[1][0];

                var frequencies = letterToFreq[1].Split(' ')
                                                 .SkipLast(1)
                                                 .Select(double.Parse)
                                                 .ToArray();
                var freqMap = new Dictionary<char, double>(letters.Length * 2);

                for (int i = 0; i < letters.Length; ++i)
                {
                    freqMap.Add(letters[i], frequencies[i]);
                }

                dict.Add((letterChar1, letterChar2), freqMap);
            }

            return dict;
        });

        private static readonly Lazy<Dictionary<char, Dictionary<char, double>>> EnglishFreq2 = new Lazy<Dictionary<char, Dictionary<char, double>>>(() =>
        {
            var lines = File.ReadAllLines("SecondOrderStatistics.txt");

            var row = lines[1].Split("||");
            if (row.Length != 2)
                throw new Exception();

            var letters = row.Last()
                             .Split('|')
                             .SkipLast(1)
                             .Select(x =>
                             {
                                 var trimmed = x.Trim();
                                 if (trimmed == "SPACE")
                                     return ' ';

                                 if (trimmed.Length != 1)
                                     throw new Exception();

                                 return trimmed[0];
                             })
                             .ToArray();

            var dict = new Dictionary<char, Dictionary<char, double>>(letters.Length * 2);

            foreach (var row2 in lines.Skip(3).SkipLast(1))
            {
                var letterToFreq = row2.Split("||");
                if (letterToFreq.Length != 2)
                    throw new Exception();

                var letterString = letterToFreq[0].Trim();

                if (letterString != "SPACE" && letterString.Length != 1)
                    throw new Exception();

                var letterChar = letterString == "SPACE" ? ' ' : letterString[0];

                var frequencies = letterToFreq[1].Split(' ')
                                                 .SkipLast(1)
                                                 .Select(double.Parse)
                                                 .ToArray();
                var freqMap = new Dictionary<char, double>(letters.Length * 2);

                for (int i = 0; i < letters.Length; ++i)
                {
                    freqMap.Add(letters[i], frequencies[i]);
                }

                dict.Add(letterChar, freqMap);
            }

            return dict;
        });

        // From http://www.data-compression.com/english.html
        private static readonly Lazy<Dictionary<char, double>> EnglishFreq = new Lazy<Dictionary<char, double>>(() =>
        {
            var lines = File.ReadAllLines("FirstOrderStatistics.txt");

            var letters = lines[1].Split('|')
                                  .Skip(1)
                                  .SkipLast(1)
                                  .Select(x =>
                                  {
                                     var trimmed = x.Trim();
                                     if (trimmed == "SPACE")
                                         return ' ';

                                     if (trimmed.Length != 1)
                                         throw new Exception();

                                     return trimmed[0];
                                  })
                                  .ToArray();

            if (lines.Length != 4)
                throw new Exception();

            var frequencies = lines[3].Split(' ')
                                      .Skip(1)
                                      .SkipLast(1)
                                      .Select(double.Parse)
                                      .ToArray();
            var freqMap = new Dictionary<char, double>(letters.Length * 2);

            for (int i = 0; i < letters.Length; ++i)
            {
                freqMap.Add(letters[i], frequencies[i]);
            }

            return freqMap;
        });

        public static List<(byte key, double score)> XorBestMatch(ReadOnlySpan<byte> xoredBytes, string expectedChars = null)
        {
            var candidates = new List<(byte key, double score)>();

            byte[] key = new byte[1];
            for (int i = 0; i < 256; ++i)
            {
                key[0] = (byte)i;
                var plainText = Xor.ApplyRepeating(xoredBytes, key);

                if (expectedChars != null && Encoding.UTF8.GetString(plainText).Any(x => !expectedChars.Contains(x)))
                    continue;

                double score = 0.0;
                foreach (var c in plainText)
                {
                    if (EnglishFreq.Value.TryGetValue(char.ToLowerInvariant((char)c), out var sc))
                        score += sc;
                }

                if (score > 0.0)
                {
                    candidates.Add((key[0], score));
                }
            }

            if (!candidates.Any())
                throw new Exception();

            return new List<(byte key, double score)>(candidates.OrderByDescending(x => x.score));
        }

        private static List<(byte key, double score)> XorBestMatch((char, byte)[] xoredBytes, string expectedChars = null)
        {
            var candidates = new List<(byte key, double score)>();

            for (int i = 0; i < 256; ++i)
            {
                var key = (byte)i;
                var plainText = xoredBytes.Select(x => (x.Item1, (char)(x.Item2 ^ key))).ToArray();

                if (expectedChars != null && plainText.Any(x => !expectedChars.Contains(x.Item2)))
                    continue;

                double score = 0.0;
                foreach (var c in plainText)
                {
                    if (EnglishFreq2.Value.TryGetValue(char.ToLowerInvariant(c.Item1), out var fr) && fr.TryGetValue(char.ToLowerInvariant(c.Item2), out var sc))
                        score += sc;
                }

                if (score > 0.0)
                {
                    candidates.Add((key, score));
                }
            }

            if (!candidates.Any())
                throw new Exception();

            return new List<(byte key, double score)>(candidates.OrderByDescending(x => x.score));
        }

        private static List<(byte key, double score)> XorBestMatch((char, char, byte)[] xoredBytes, string expectedChars = null)
        {
            var candidates = new List<(byte key, double score)>();

            for (int i = 0; i < 256; ++i)
            {
                var key = (byte)i;
                var plainText = xoredBytes.Select(x => (x.Item1, x.Item2, (char)(x.Item3 ^ key))).ToArray();

                if (expectedChars != null && plainText.Any(x => !expectedChars.Contains(x.Item3)))
                    continue;

                double score = 0.0;
                foreach (var c in plainText)
                {
                    if (EnglishFreq3.Value.TryGetValue((char.ToLowerInvariant(c.Item1), char.ToLowerInvariant(c.Item2)), out var fr) &&
                        fr.TryGetValue(char.ToLowerInvariant(c.Item3), out var sc))
                    {
                        score += sc;
                    }
                }

                if (score > 0.0)
                {
                    candidates.Add((key, score));
                }
            }

            return new List<(byte key, double score)>(candidates.OrderByDescending(x => x.score));
        }

        public static byte[] GetCommonKeyStream(List<byte[]> encryptedLines, string expectedChars)
        {
            var candidates = new List<byte>();
            var keySteam = new List<(byte key, double score)>[encryptedLines.Max(x => x.Length)];

            int i = 0;
            while (true)
            {
                candidates.Clear();

                if (encryptedLines.TrueForAll(x => x.Length <= i))
                    break;

                for (int b = 0; b < 256; ++b)
                {
                    if (encryptedLines.TrueForAll(x =>
                                                    {
                                                        if (x.Length <= i)
                                                            return true;

                                                        return expectedChars.Contains(Convert.ToChar((byte)(x[i] ^ b)));
                                                    }))
                    {
                        candidates.Add((byte)b);
                    }
                }

                if (candidates.Count > 1)
                {
                    if (i == 0)
                    {
                        keySteam[i] = Xor.XorBestMatch(encryptedLines.Where(x => x.Length > i)
                                                                     .Select(x => x[i])
                                                                     .ToArray());
                    }
                    else if (i == 1)
                    {
                        keySteam[i] = Xor.XorBestMatch(encryptedLines.Where(x => x.Length > i)
                                                                     .Select(x => ((char)(x[i - 1] ^ keySteam[i - 1].First().key), x[i]))
                                                                     .ToArray(),
                                                       expectedChars);
                    }
                    else
                    {
                        var matches = Xor.XorBestMatch(encryptedLines.Where(x => x.Length > i)
                                                                     .Select(x => ((char)(x[i - 2] ^ keySteam[i - 2].First().key), (char)(x[i - 1] ^ keySteam[i - 1].First().key), x[i]))
                                                                     .ToArray(),
                                                       expectedChars);

                        if (!matches.Any())
                        {
                            keySteam[i - 1].RemoveAt(0);
                            continue;
                        }

                        keySteam[i] = matches;
                    }
                }
                else
                {
                    keySteam[i] = new List<(byte key, double score)>{ (candidates[0], double.MaxValue) };
                }

                ++i;
            }

            return keySteam.Select(x => x.First().key).ToArray();
        }

        public static int GuessRepeatingKeyLength(ReadOnlySpan<byte> cipher, int maxKeyLength)
        {
            var candidates = new Dictionary<int, double>(maxKeyLength);
            for (int i = 2; i <= maxKeyLength; ++i)
            {
                if (cipher.Length / i < 2)
                    break;

                var distances = new double[cipher.Length / i - 1];
                for (int segment = 0; segment < distances.Length; ++segment)
                {
                    distances[segment] = Hamming.GetDistance(cipher.Slice(segment * i, i), cipher.Slice((segment + 1) * i, i)) / (double)i;
                }

                candidates[i] = distances.Average();
            }

            var len = candidates.OrderByDescending(x => x.Value).Last().Key;
            return len;
        }

        public static byte[] BreakRepeating(/*byte[]*/ReadOnlySpan<byte> cipher, int keyLength, string expectedChars = null)
        {
            var keySteam = new List<(byte key, double score)>[keyLength];
            byte[] blockMinusOne = null, blockMinusTwo = null;

            for (int i = 0; i < keyLength; ++i)
            {
                //var block = cipher.Where((x, n) => n % keyLength == i).ToArray();
                var block = new byte[cipher.Length / keyLength + (cipher.Length % keyLength != 0 ? 1 : 0)];
                for (int j = i, b = 0; j < cipher.Length; j += keyLength, ++b)
                {
                    block[b] = cipher[j];
                }

                if (i == 0)
                    keySteam[i] = Xor.XorBestMatch(block, expectedChars);
                else if (i == 1)
                    keySteam[i] = Xor.XorBestMatch(block.Select((x, n) => ((char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x)).ToArray(), expectedChars);
                else
                {
                    var candidates = Xor.XorBestMatch(block.Select((x, n) => ((char)(blockMinusTwo[n] ^ keySteam[i - 2].First().key),
                                                                              (char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x))
                                                           .ToArray(), expectedChars);

                    //if (!candidates.Any())
                    //{
                    //    keySteam[--i].RemoveAt(0);
                    //    continue;
                    //}

                    if (!candidates.Any())
                        candidates = Xor.XorBestMatch(block.Select((x, n) => ((char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x)).ToArray(), expectedChars);

                    if (!candidates.Any())
                        candidates = Xor.XorBestMatch(block, expectedChars);

                    keySteam[i] = candidates;
                }

                blockMinusTwo = blockMinusOne;
                blockMinusOne = block;
            }

            return keySteam.Select(x => x.First().key).ToArray();
        }
    }

    public class MT19937
    {
        private const uint w = 32U, n = 624U, m = 397U, r = 31U, f = 1812433253U;

        private const int u = 11, s = 7, t = 15, l = 18;

        private const uint d = 0xFFFFFFFFU, a = 0x9908B0DFU, b = 0x9D2C5680U, c = 0xEFC60000U;

        private readonly uint[] MT = new uint[n]; // Create a length n array to store the state of the generator

        private uint index = n + 1;

        private const uint lower_mask = unchecked ((1 << (int)r) - 1); // That is, the binary number of r 1's
        private const uint upper_mask = ~lower_mask & 0xffffffffU; // lowest w bits of (not lower_mask)

        // Initialize the generator from a seed
        public void seed_mt(uint seed)
        {
            index = n;
            MT[0] = seed;

            for (int i = 1; i < MT.Length; ++i)
                MT[i] = (uint)(0xffffffffU & (f * (MT[i - 1] ^ (MT[i - 1] >> (int)(w - 2))) + i));
        }

        // Extract a tempered value based on MT[index]
        // calling twist() every n numbers
        public uint extract_number()
        {
            if (index >= n)
            {
                if (index > n)
                {
                    throw new Exception("Generator was never seeded");
                    // Alternatively, seed with constant value; 5489 is used in reference C code[46]
                }
                twist();
            }

            uint y = MT[index];
            y = y ^ ((y >> u) & d);
            y = y ^ ((y << s) & b);
            y = y ^ ((y << t) & c);
            y = y ^ (y >> l);

            ++index;
            return 0xffffffffU & y;
        }

        // Generate the next n values from the series x_i
        public void twist()
        {
            for (int i = 0; i < n; ++i)
            {
                uint x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask);
                uint xA = x >> 1;

                if ((x % 2) != 0)
                {
                    // lowest bit of x is 1
                    xA = xA ^ a;
                }
                MT[i] = MT[(i + m) % n] ^ xA;
            }
            index = 0;
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

    public static class CbcPaddingOracle
    {
        public static ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> iv, byte[] key)
        {
            if (encrypted.Length % 16 != 0)
                throw new Exception();

            var decrypted = new byte[encrypted.Length];

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block >= 0; --block)
            {
                Span<byte> prevBlock = new byte[16];
                if (block == 0)
                    iv.CopyTo(prevBlock);
                else
                    encrypted.Slice((block - 1) * 16, 16).CopyTo(prevBlock);

                var blockCopy = new byte[16];
                prevBlock.CopyTo(blockCopy);

                for (int i = 15; i >= 0; --i,
                                         blockCopy.CopyTo(prevBlock))
                {
                    // set bytes past the current index to produce needed padding as
                    // "0x02" or "0x03 0x03" or "0x04 0x04 0x04" etc.
                    // by using already decrypted values
                    for (int n = 15; n > i; --n)
                    {
                        prevBlock[n] = (byte)(blockCopy[n] ^ decrypted[block * 16 + n] ^ (16 - i));
                    }

                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("byte wasn't found");

                        prevBlock[i] = (byte)b;
                        if (Validate(encrypted.Slice(block * 16, 16), prevBlock, key))
                        {
                            if (i != 0)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02"
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                prevBlock[i - 1] += 1;
                                if (!Validate(encrypted.Slice(block * 16, 16), prevBlock, key))
                                    continue;
                            }

                            decrypted[block * 16 + i] = (byte)(b ^ (16 - i) ^ blockCopy[i]);
                            break;
                        }
                    }
                }
            }

            return PKCS7.StripPad(decrypted);
        }

        private static bool Validate(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> iv, byte[] key)
        {
            try
            {
                MyAes.DecryptCbcPkcs7(encrypted, iv, key);
                return true;
            }
            catch (CryptographicException e) when (e.Message == "Padding is invalid and cannot be removed.")
            {
                return false;
            }
        }
    }

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

    public static class RandomEncryptor
    {
        public static (byte[] cipher, CipherMode mode) Encrypt(ReadOnlySpan<byte> plainText)
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
                plainText.CopyTo(appended.AsSpan(before.Length));
                Array.Copy(after, 0, appended, before.Length + plainText.Length, after.Length);

                var m = rnd.GetInt(0, 1);
                var mode = m % 2 == 0 ? CipherMode.CBC : CipherMode.ECB;
                return (mode == CipherMode.CBC ? MyAes.EncryptCbcPkcs7(appended, IV, key) : MyAes.EncryptEcb(appended, key), mode);
            }
        }

        private static readonly byte[] IV = new byte[16];
    }

    public static class HttpQuery
    {
        public static List<(string key, string value)> Parse(string query, char pairDelimiter = '&', char keyValueDelimiter = '=')
        {
            var obj = new List<(string key, string value)>();
            foreach (var pair in query.Split(pairDelimiter))
            {
                var keyVal = pair.Split(keyValueDelimiter);
                if (keyVal.Length != 2)
                    throw new Exception();

                obj.Add((keyVal[0], keyVal[1]));
            }

            return obj;
        }

        public static string Compile(List<(string key, string value)> obj, char pairDelimiter = '&', char keyValueDelimiter = '=')
        {
            var query = new StringBuilder();
            foreach (var pair in obj)
            {
                if (query.Length != 0)
                    query.Append(pairDelimiter);

                query.Append($"{pair.key}{keyValueDelimiter}{pair.value}");
            }

            return query.ToString();
        }
    }

    public class UserProfileOracle
    {
        private readonly byte[] Key;

        public UserProfileOracle()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                Key = new byte[16];
                rnd.GetBytes(Key);
            }
        }

        public byte[] CreateFor(string email)
        {
            if (email.Any(x => x == '&' || x == '='))
                throw new Exception();

            var obj = new List<(string key, string value)>(3)
            {
                ("email", email),
                ("uid", "10"),
                ("role", "user")
            };

            return MyAes.EncryptEcb(Encoding.UTF8.GetBytes(HttpQuery.Compile(obj)), Key);
        }

        public List<(string key, string value)> Decrypt(ReadOnlySpan<byte> cipher)
        {
            var plainText = Encoding.UTF8.GetString(MyAes.DecryptEcb(cipher, Key));
            return HttpQuery.Parse(plainText);
        }
    }
}
