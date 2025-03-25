using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MatasanoCryptoChallenge;
using MyCrypto;
using Xunit;

namespace Tests
{
    /*
    This is the next set of **block cipher cryptography** challenges
    (even the randomness stuff here plays into block cipher crypto).

    This set is **moderately difficult**.
    It includes a famous attack against CBC mode,
    and a "cloning" attack on a popular RNG that can be annoying to get right.

    We've also reached a point in the crypto challenges where all the challenges,
    with one possible exception, are valuable in breaking real-world crypto.
    */
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
                Assert.Equal(input, decrypted);
            }
        }

        /*
        The CBC padding oracle

        This is the best-known attack on modern block-cipher cryptography.

        Combine your padding code and your CBC code to write two functions.

        The first function should select at random one of the following 10 strings:

        MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
        MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
        MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
        MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
        MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
        MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
        MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
        MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
        MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
        MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

        ... generate a random AES key (which it should save for all future encryptions),
        pad the string out to the 16-byte AES block size and CBC-encrypt it under that key,
        providing the caller the ciphertext and IV.

        The second function should consume the ciphertext produced by the first function, decrypt it,
        check its padding, and return true or false depending on whether the padding is valid.

        What you're doing here.
        This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications;
        the second function models the server's consumption of an encrypted session token, as if it was a cookie.

        It turns out that it's possible to decrypt the ciphertexts provided by the first function.

        The decryption here depends on a side-channel leak by the decryption function.
        The leak is the error message that the padding is valid or not.

        You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

        The fundamental insight behind this attack is that the byte 01h is valid padding,
        and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

        02h in isolation is _not_ valid padding.

        02h 02h _is_ valid padding, but is much less likely to occur randomly than 01h.

        03h 03h 03h is even less likely.

        So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

        It is easy to get tripped up on the fact that CBC plaintexts are "padded".
        _Padding oracles have nothing to do with the actual padding on a CBC plaintext_.
        It's an attack that targets a specific bit of code that handles decryption.
        You can mount a padding oracle on any CBC block, whether it's padded or not.
        */
        [Fact]
        public void Challenge17_CBC_padding_oracle_decrypt()
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
                    var decrypted = CbcPaddingOracle.Decrypt(encrypted, ValidateOracle, iv);
                    Assert.Equal(input, decrypted);
                }
            }
        }

        /*
        Same as above but when we don't know IV (it is server only). The first block will be a garbage.
        */
        [Fact]
        public void Challenge17_2_CBC_padding_oracle_decrypt_no_IV()
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

                    bool ValidateOracle(ReadOnlySpan<byte> encrypted, ReadOnlySpan<byte> _)
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
                    var decrypted = CbcPaddingOracle.Decrypt(encrypted, ValidateOracle);
                    // since we don't know the IV the first block will be a garbage
                    Assert.Equal(input.AsSpan(16), decrypted.Slice(16));
                }
            }
        }

        /*
        Inspired by https://www.skullsecurity.org/2016/going-the-other-way-with-padding-oracles-encrypting-arbitrary-data and
        https://blog.teddykatz.com/2019/11/23/json-padding-oracles.html

        In the previous example we used a padding info leaking oracle to decrypt the message.

        The same technique can be used to create an encrypted message that will be decrypted into a chosen plaintext!

        If the IV is supplied with the encrypted message, we can produce a clean message.
        If the IV is unknown (server only) one block will always contain garbage.

        First, write a function that takes a user name ang produces a json in a form of `{ time: <timestamp>, username: <username> }`.
        Where `time` is a unix timestamp when the json was generated.

        Then write a function that parses the json and validates if the timestamp is not older that 30 days and the user name is "admin".

        Call the first function to generate the json for user "anonymous" and CBC encrypt it with random Key and IV.
        This is a server generated token.

        Write a function that takes the token and returns true if it can decrypt it with the unknown to you Key and IV,
        but returns false if the padding is invalid. This is a server side padding oracle you need to exploit.

        To encrypt arbitrary text with a padding oracle:

            * Select a string, P, that you want to generate ciphertext, C, for

            * Pad the string to be a multiple of the blocksize, using appropriate padding,
              then split it into blocks numbered from 1 to N

            * Generate a block of random data (Cn - ultimately, the final block of ciphertext)

            * For each block of plaintext, starting with the last one:

                * Create a two-block string of ciphertext, C', by combining an empty block (00000...)
                  with the most recently generated ciphertext block (Cn+1) (or the random one if it's the first round)

                * Change the last byte of the empty block until the padding errors go away,
                  then use math (see below for way more detail) to set the last byte to 2 and
                  change the second-last byte till it works.
                  Then change the last two bytes to 3 and figure out the third-last, fourth-last, etc.

                * After determining the full block, XOR it with the plaintext block Pn to create Cn

                * Repeat the above process for each block (prepend an empty block to the new ciphertext block, calculate it, etc)

        To put that in English: each block of ciphertext decrypts to an unknown value,
        then is XOR’d with the previous block of ciphertext.
        By carefully selecting the previous block, we can control what the next block decrypts to.
        Even if the next block decrypts to a bunch of garbage, it’s still being XOR’d to a value that we control,
        and can therefore be set to anything we want.
        */
        [Fact]
        public void Challenge17_3_CBC_padding_oracle_encrypt()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                var iv = new byte[16];
                rnd.GetBytes(iv);

                bool ValidateOracle(ReadOnlySpan<byte> encrypted)
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

                var anonymousJson = UserJsonToken.CreateFor("anonymous");
                Assert.True(UserJsonToken.Validate(anonymousJson, "anonymous"));
                var anonymousToken = MyAes.EncryptCbcPkcs7(Encoding.UTF8.GetBytes(anonymousJson), iv, key);

                var payload = "\",\"user\":\"admin\"}";

                while(true)
                {
                    try
                    {
                        var encryptedPayload = CbcPaddingOracle.Encrypt(Encoding.UTF8.GetBytes(payload), ValidateOracle);
                        var encrypted = new byte[32 + encryptedPayload.Length];
                        // The fact that two messages were encrypted with the same IV
                        // means the blocks are the same for the same data (timestamps).
                        // Cut the first two blocks of the anonymousToken chipher which ends at `"user":"an`
                        Array.Copy(anonymousToken, encrypted, 32);
                        // and append our encrypted `","user":"admin"}`
                        encryptedPayload.CopyTo(encrypted.AsSpan(32));

                        var decryptedPayload = Encoding.UTF8.GetString(MyAes.DecryptCbcPkcs7(encryptedPayload, iv, key));
                        Assert.EndsWith(payload, decryptedPayload); // the first block is always garbage because we don't know the IV

                        var decryptedJson = Encoding.UTF8.GetString(MyAes.DecryptCbcPkcs7(encrypted, iv, key));
                        // we have two "user" fields in the json. The first one has a garbage value, but the second always wins
                        Assert.True(UserJsonToken.Validate(decryptedJson, "admin"));
                        break;
                    }
                    catch (JsonException)
                    {
                        // we have ~10% chance of success because the generated garbage block may be an invalid JSON string
                        continue;
                    }
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

        [Fact]
        public void Challenge19_Fixed_Nonce_CTR_Substitutions()
        {
            var (encryptedLines, plainTextLines) = ReadAndEncryptWithCTR("Data/19.txt", 0);

            var expectedChars = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-'\".,:;!? ";

            var keystream = XorBreaker.GetCommonKeyStream(encryptedLines, expectedChars);

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

                var key = XorBreaker.BreakRepeating(cipher, i, expectedChars);
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
