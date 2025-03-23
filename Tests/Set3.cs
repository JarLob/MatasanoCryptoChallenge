using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MatasanoCryptoChallenge;
using Xunit;
using Xunit.Abstractions;

namespace Tests
{
    public class Set3
    {
        [Fact]
        public void CbcCustomEncryptLibraryDecrypt()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                var input = new byte[42];
                rnd.GetBytes(input);

                var key = new byte[16];
                rnd.GetBytes(key);

                var iv = new byte[16];
                rnd.GetBytes(iv);

                var encrypted = MyAes._CustomEncryptCbcPkcs7(input, iv, key);
                var decrypted = MyAes._LibraryDecrypt(encrypted, iv, key, CipherMode.CBC);
                Assert.Equal(input, decrypted);
            }
        }

        [Fact]
        public void CbcLibraryEncryptCustomDecrypt()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                var input = new byte[42];
                rnd.GetBytes(input);

                var key = new byte[16];
                rnd.GetBytes(key);

                var iv = new byte[16];
                rnd.GetBytes(iv);

                var encrypted = MyAes._LibraryEncrypt(input, iv, key, CipherMode.CBC);
                var decrypted = MyAes._CustomDecryptCbcPkcs7(encrypted, iv, key);
                Assert.Equal(input, decrypted.ToArray());
            }
        }

        [Fact]
        public void Challenge17_CBC_padding_oracle()
        {
            var lines = File.ReadAllLines("Data/17.txt");

            using (var rnd = RandomNumberGenerator.Create())
            {
                //var input = Convert.FromBase64String(lines[rnd.GetInt(0, lines.Length)]);

                foreach (var line in lines)
                {
                    var input = Convert.FromBase64String(line);

                    var key = new byte[16];
                    rnd.GetBytes(key);

                    var iv = new byte[16];
                    rnd.GetBytes(iv);

                    bool ValidateOracle(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> iv)
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

                    var encrypted = MyAes.EncryptCbcPkcs7(input, iv, key);
                    var decrypted = CbcPaddingOracle.Decrypt(encrypted, iv, ValidateOracle);
                    Assert.Equal(input, decrypted.ToArray());
                }
            }
        }

        [Fact]
        public void Challenge18_CTR_stream_cipher_mode()
        {
            var input = Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
            ulong nonce = 0;
            var key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");

            Assert.Equal("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", Encoding.UTF8.GetString(MyAes.EncryptDecryptCtr(input, nonce, key)));

            nonce = 13;
            var plainText = "test";
            var encrypted = MyAes.EncryptDecryptCtr(Encoding.UTF8.GetBytes(plainText), nonce, key);
            Assert.Equal(plainText, Encoding.UTF8.GetString(MyAes.EncryptDecryptCtr(encrypted, nonce, key)));
        }

        private (List<byte[]> encryptedLines, List<string> plainTextLines) ReadAndEncryptWithCTR(string fileName, ulong nonce)
        {
            var lines = File.ReadAllLines(fileName);
            var encryptedLines = new List<byte[]>(lines.Length);
            var plainTextLines = new List<string>(lines.Length);

            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];// { (byte)0x03, (byte)0x39, (byte)0x1e, (byte)0xb9, (byte)0x0f, (byte)0xf7, (byte)0xbc, (byte)0xe4, (byte)0x77, (byte)0x3e, (byte)0x9f, (byte)0x58, (byte)0xcc, (byte)0x9c, (byte)0xd3, (byte)0x28 }; ;
                rnd.GetBytes(key);

                foreach (var line in lines)
                {
                    var plainBytes = Convert.FromBase64String(line);
                    var plainText = Encoding.UTF8.GetString(plainBytes);
                    plainTextLines.Add(plainText);
                    var encrypted = MyAes.EncryptDecryptCtr(plainBytes, nonce, key);
                    encryptedLines.Add(encrypted);
                }
            }

            return (encryptedLines, plainTextLines);
        }

        private readonly ITestOutputHelper output;

        public Set3(ITestOutputHelper output)
        {
            this.output = output;
        }

        [Fact]
        public void Challenge19_Fixed_Nonce_CTR_Substitutions()
        {
            var (encryptedLines, plainTextLines) = ReadAndEncryptWithCTR("Data/19.txt", 0);

            var expectedChars = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-'\".,:;!? ";

            var keystream = Xor.GetCommonKeyStream(encryptedLines, expectedChars);

            for (int j = 0; j < encryptedLines.Count; j++)
            {
                byte[] encryptedLine = encryptedLines[j];
                var line = new char[encryptedLine.Length];
                for (int i = 0; i < encryptedLine.Length; ++i)
                    line[i] = Convert.ToChar((byte)(encryptedLine[i] ^ keystream[i]));

                var decryptedLowerCase = new string(line).ToLowerInvariant();
                var originalLowerCase = plainTextLines[j].ToLowerInvariant();

                switch (j)
                {
                    case 4:
                        //            i have passed with a nod of the head
                        Assert.Equal("i have passed with a nod of the hiln", decryptedLowerCase);
                        break;
                    case 27:
                        //            he might have won fame in the end,
                        Assert.Equal("he might have won fame in the end ", decryptedLowerCase);
                        break;
                    case 37:
                        //            he, too, has been changed in his turn,
                        Assert.Equal("he, too, has been changed in his xxxis", decryptedLowerCase);
                        break;
                    default:
                        Assert.Equal(originalLowerCase, decryptedLowerCase);
                        break;
                }
            }
        }

        [Fact]
        public void Challenge20_Fixed_Nonce_CTR_Statistically()
        {
            var (encryptedLines, plainTextLines) = ReadAndEncryptWithCTR("Data/20.txt", 0);

            var minLength = encryptedLines.Min(x => x.Length);
            var maxLength = encryptedLines.Max(x => x.Length);
            var expectedChars = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-'\".,:;!? /";

            var keystream = new List<byte>(maxLength);

            for (int i = minLength; i <= maxLength; ++i)
            {
                var cipher = encryptedLines.Where(x => x.Length >= i)
                                           .Select(x => x.Take(i))
                                           .SelectMany(x => x)
                                           .ToArray();

                var key = Xor.BreakRepeating(cipher, i, expectedChars);
                if (i == minLength)
                    keystream.AddRange(key);
                else
                    keystream.Add(key[i - 1]);
            }

            for (int j = 0; j < encryptedLines.Count; j++)
            {
                byte[] encryptedLine = encryptedLines[j];
                var line = new char[encryptedLine.Length];
                for (int i = 0; i < line.Length; ++i)
                    line[i] = Convert.ToChar((byte)(encryptedLine[i] ^ keystream[i]));

                var decryptedLowerCase = new string(line).ToLowerInvariant();
                var originalLowerCase = plainTextLines[j].ToLowerInvariant();

                switch (j)
                {
                    case 21:
                        //            shake 'till your clear, make it disappear, make the next / after the ceremony, let the rhyme rest in peace
                        Assert.Equal("shake 'till your clear, make it disappear, make the next / after the ceremony, let the rhyme rest iy peace", decryptedLowerCase);
                        break;
                    case 26:
                        Assert.Equal(new string(originalLowerCase.Replace("observe", "observr").SkipLast(12).ToArray()), new string(decryptedLowerCase.SkipLast(12).ToArray()));
                        break;
                    case 29:
                        //            program into the speed of the rhyme, prepare to start / rhythm's out of the radius, insane as the craziest
                        Assert.Equal("program into the speed of the rhyme, prepare to start / rhythm's out of the radius, insane as the ceaziest", decryptedLowerCase);
                        break;
                    case 41:
                        //            i wanna hear some of them def rhymes, you know what i'm sayin'? / and together, we can get paid in full
                        Assert.Equal("i wanna hear some of them def rhymes, you know what i'm sayin'? / and together, we can get paid in qull", decryptedLowerCase);
                        break;
                    case 46:
                        Assert.Equal(new string(originalLowerCase.Replace("move", "mxve").SkipLast(10).ToArray()), new string(decryptedLowerCase.SkipLast(10).ToArray()));
                        break;
                    default:
                        Assert.Equal(originalLowerCase, decryptedLowerCase);
                        break;
                }
            }
        }

        [Fact]
        public void Challenge21_Implement_the_MT19937_Mersenne_Twister_RNG()
        {
            var rng = new MT19937();
            rng.SeedMt(5489);

            var list1 = new List<uint>(1000);
            for (int i = 0; i < 1000; ++i)
                list1.Add(rng.ExtractNumber());

            var rng2 = new MT19937();
            rng2.SeedMt(5489);

            var list2 = new List<uint>(1000);
            for (int i = 0; i < 1000; ++i)
                list2.Add(rng2.ExtractNumber());

            Assert.Equal(list1, list2);
            Assert.Equal(list1.Take(10), new uint[] { 0xD091BB5C, 0x22AE9EF6, 0xE7E1FAEE, 0xD5C31F79, 0x2082352C, 0xF807B7DF, 0xE9D30005, 0x3895AFE1, 0xA1E24BBA, 0x4EE4092B });
        }

        [Fact]
        public void Challenge22_Crack_an_MT19937_seed()
        {
            int unixTimestamp;
            uint seed;
            uint currentRandomNumber;

            using (var crnd = RandomNumberGenerator.Create())
            {
                unixTimestamp = (int)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
                unixTimestamp += CryptoRandom.GetInt(crnd, 40, 1000);

                var rng = new MT19937();
                seed = (uint)unixTimestamp;
                rng.SeedMt(seed);

                unixTimestamp += CryptoRandom.GetInt(crnd, 40, 1000);
                currentRandomNumber = rng.ExtractNumber();
            }

            // check every possible second from the last twenty-four hours
            uint foundSeed = 0;
            for (int i = unixTimestamp; i > (unixTimestamp - 86400); --i)
            {
                var rng = new MT19937();
                rng.SeedMt((uint)i);

                if (rng.ExtractNumber() == currentRandomNumber)
                {
                    foundSeed = (uint)i;
                    break;
                }
            }

            Assert.Equal(seed, foundSeed);
        }

        [Fact]
        public void Challenge23_Clone_an_MT19937_RNG_from_its_output()
        {
            var rng = new MT19937();
            rng.SeedMt(5489);

            // run random number of ExtractNumber
            // the cloning doesn't depend on internal index state
            using (var crnd = RandomNumberGenerator.Create())
            {
                var runCount = CryptoRandom.GetInt(crnd, 1, 2000);
                for (int i = 0; i < runCount; ++i)
                    rng.ExtractNumber();
            }

            var states = new List<uint>(624);
            for (int i = 0; i < states.Capacity; ++i)
            {
                states.Add(rng.ExtractNumber());
            }

            var clone = MT19937Cloner.Clone(states);
            for (int i = 0; i < 1000; ++i)
            {
                Assert.Equal(rng.ExtractNumber(), clone.ExtractNumber());
            }
        }
    }
}
