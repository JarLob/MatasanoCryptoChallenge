using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MatasanoCryptoChallenge;
using Xunit;

namespace Tests
{
    public class Set1
    {
        [Fact]
        public void Challenge01_HexToBase64()
        {
            Assert.Equal("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
                         Convert.ToBase64String(Hex.ToBytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")));
        }

        [Fact]
        public void Challenge02_FixedXOR()
        {
            var xored = Xor.ApplyFixed(Hex.ToBytes("1c0111001f010100061a024b53535009181c"), Hex.ToBytes("686974207468652062756c6c277320657965"));
            Assert.Equal("746865206b696420646f6e277420706c6179",
                         BitConverter.ToString(xored).Replace("-", "").ToLowerInvariant());
        }

        [Fact]
        public void Challenge03_SingleByteBreakXOR()
        {
            Assert.Equal("Cooking MC's like a pound of bacon",
                         Xor.XorBestMatch(Hex.ToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")).plainText);
        }

        [Fact]
        public void Challenge04_FindXORInFile()
        {
            var lines      = File.ReadAllLines("4.txt");
            var candidates = new List<(string plainText, byte key, double score)>(lines.Length);
            foreach (var line in lines)
            {
                candidates.Add(Xor.XorBestMatch(Hex.ToBytes(line)));
            }

            Assert.Equal("Now that the party is jumping\n", candidates.OrderByDescending(x => x.score).First().plainText);
        }

        [Fact]
        public void Challenge05_RepeatingXOR()
        {
            Assert.Equal("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
                         Hex.ToString(Xor.ApplyRepeating(Encoding.UTF8.GetBytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), Encoding.UTF8.GetBytes("ICE"))));
        }

        [Fact]
        public void Challenge06_BreakRepeatingXOR()
        {
            //Console.WriteLine(Utils.GetHammingDistance(Encoding.UTF8.GetBytes("this is a test"),
            //                                           Encoding.UTF8.GetBytes("wokka wokka!!!")));

            var base64 = File.ReadAllText("6.txt").Replace("\n", "");
            var cipher = Convert.FromBase64String(base64);

            var candidates = new Dictionary<int, double>(40);
            for (int i = 2; i < 41; ++i)
            {
                if (cipher.Length / i < 2)
                    break;

                var distances = new double[cipher.Length / i - 1];
                for (int segment = 0; segment < distances.Length; ++segment)
                {
                    distances[segment] = Hamming.GetDistance(cipher.AsSpan(segment * i, i), cipher.AsSpan((segment + 1) * i, i)) / (double)i;
                }

                candidates[i] = distances.Average();
            }

            var len = candidates.OrderByDescending(x => x.Value).Last().Key;
            var key = new byte[len];

            for (int k = 0; k < len; ++k)
            {
                var block = cipher.Where((x, i) => i % len == k).ToArray();
                key[k] = Xor.XorBestMatch(block).key;
            }

            Assert.Equal("Terminator X: Bring the noise", Encoding.UTF8.GetString(key));

            //Console.WriteLine($"Password:\"{Encoding.UTF8.GetString(key)}\"");
            //Console.WriteLine(Set1.XORDecrypt(cipher, key));
        }

        [Fact]
        public void Challenge07_DecryptAesEcb()
        {
            var base64 = File.ReadAllText("7.txt").Replace("\n", "");
            var cipher = Convert.FromBase64String(base64);
            Assert.Equal("I'm back and I'm ringin' the bell ",
                         Encoding.UTF8.GetString(MyAes.DecryptEcb(cipher,
                                                                  Encoding.UTF8.GetBytes("YELLOW SUBMARINE"))).Split('\n')[0]);
        }

        [Fact]
        public void Challenge08_DetectEcb()
        {
            var lines      = File.ReadAllLines("8.txt");
            var candidates = new Dictionary<int, double>(lines.Length);

            for (var i = 0; i < lines.Length; i++)
            {
                var line   = lines[i];
                var cipher = Hex.ToBytes(line);

                var same = new HashSet<int>(cipher.Length / 16);
                for (int segment1 = 0; segment1 < cipher.Length / 16; ++segment1)
                {
                    if (same.Contains(segment1))
                        continue;

                    for (int segment2 = segment1 + 1; segment2 < cipher.Length / 16; ++segment2)
                    {
                        if (same.Contains(segment2))
                            continue;

                        if (0 == Hamming.GetDistance(cipher.AsSpan(segment1 * 16, 16), cipher.AsSpan((segment2) * 16, 16)))
                        {
                            same.Add(segment1);
                            same.Add(segment2);
                        }
                    }
                }

                candidates[i + 1] = same.Count;
            }

            var lnNr = candidates.OrderByDescending(x => x.Value).First().Key;

            Assert.Equal(133, lnNr);
        }
    }
}
