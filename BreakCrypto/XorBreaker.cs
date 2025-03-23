using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class XorBreaker
    {
        private static readonly Lazy<Dictionary<(char, char), Dictionary<char, double>>> EnglishFreq3 = new Lazy<Dictionary<(char, char), Dictionary<char, double>>>(() =>
        {
            var lines = File.ReadAllLines("Data/ThirdOrderStatistics.txt");

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
            var lines = File.ReadAllLines("Data/SecondOrderStatistics.txt");

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
            var lines = File.ReadAllLines("Data/FirstOrderStatistics.txt");

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

        public static List<(byte key, double score)> BestMatch(ReadOnlySpan<byte> xoredBytes, string expectedChars = null)
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

        private static List<(byte key, double score)> BestMatch((char, byte)[] xoredBytes, string expectedChars = null)
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

        private static List<(byte key, double score)> BestMatch((char, char, byte)[] xoredBytes, string expectedChars = null)
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
                        keySteam[i] = XorBreaker.BestMatch(encryptedLines.Where(x => x.Length > i)
                                                                     .Select(x => x[i])
                                                                     .ToArray());
                    }
                    else if (i == 1)
                    {
                        keySteam[i] = XorBreaker.BestMatch(encryptedLines.Where(x => x.Length > i)
                                                                     .Select(x => ((char)(x[i - 1] ^ keySteam[i - 1].First().key), x[i]))
                                                                     .ToArray(),
                                                       expectedChars);
                    }
                    else
                    {
                        var matches = XorBreaker.BestMatch(encryptedLines.Where(x => x.Length > i)
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
                    keySteam[i] = new List<(byte key, double score)> { (candidates[0], double.MaxValue) };
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
                    keySteam[i] = XorBreaker.BestMatch(block, expectedChars);
                else if (i == 1)
                    keySteam[i] = XorBreaker.BestMatch(block.Select((x, n) => ((char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x)).ToArray(), expectedChars);
                else
                {
                    var candidates = XorBreaker.BestMatch(block.Select((x, n) => ((char)(blockMinusTwo[n] ^ keySteam[i - 2].First().key),
                                                                              (char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x))
                                                           .ToArray(), expectedChars);

                    //if (!candidates.Any())
                    //{
                    //    keySteam[--i].RemoveAt(0);
                    //    continue;
                    //}

                    if (!candidates.Any())
                        candidates = XorBreaker.BestMatch(block.Select((x, n) => ((char)(blockMinusOne[n] ^ keySteam[i - 1].First().key), x)).ToArray(), expectedChars);

                    if (!candidates.Any())
                        candidates = XorBreaker.BestMatch(block, expectedChars);

                    keySteam[i] = candidates;
                }

                blockMinusTwo = blockMinusOne;
                blockMinusOne = block;
            }

            return keySteam.Select(x => x.First().key).ToArray();
        }
    }
}
