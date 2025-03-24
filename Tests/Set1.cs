using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using MatasanoCryptoChallenge;
using MyCrypto;
using Xunit;

namespace Tests
{
    /*
    This is the **qualifying set**.
    We picked the exercises in it to ramp developers up gradually into coding cryptography,
    but also to verify that we were working with people who were ready to write code.

    This set is **relatively easy**.
    With one exception, most of these exercises should take only a couple minutes.
    But don't beat yourself up if it takes longer than that. It took Alex two weeks to get through the set!

    If you've written any crypto code in the past, you're going to feel like skipping a lot of this.
    Don't skip them. At least two of them (we won't say which) are important stepping stones to later attacks.
    */
    public class Set1
    {
        /*
        Convert hex to base64

        The string:
        49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

        Should produce:
        SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

        So go ahead and make that happen.You'll need to use this code for the rest of the exercises.

        Cryptopals Rule
        Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
        */
        [Fact]
        public void Challenge01_HexToBase64()
        {
            Assert.Equal("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
                         Convert.ToBase64String(Hex.ToBytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")));
        }

        /*
        Fixed XOR

        Write a function that takes two equal-length buffers and produces their XOR combination.

        If your function works properly, then when you feed it the string:
        1c0111001f010100061a024b53535009181c

        ... after hex decoding, and when XOR'd against:
        686974207468652062756c6c277320657965

        ... should produce:
        746865206b696420646f6e277420706c6179
        */
        [Fact]
        public void Challenge02_FixedXOR()
        {
            var xored = Xor.ApplyFixed(Hex.ToBytes("1c0111001f010100061a024b53535009181c"), Hex.ToBytes("686974207468652062756c6c277320657965"));
            Assert.Equal("746865206b696420646f6e277420706c6179",
                         BitConverter.ToString(xored).Replace("-", "").ToLowerInvariant());
        }

        /*
        Single-byte XOR cipher

        The hex encoded string:
        1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

        ... has been XOR'd against a single character. Find the key, decrypt the message.

        You can do this by hand. But don't: write code to do it for you.

        How? Devise some method for "scoring" a piece of English plaintext.
        Character frequency is a good metric. Evaluate each output and choose the one with the best score.

        Achievement Unlocked
        You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
        */
        [Fact]
        public void Challenge03_SingleByteBreakXOR()
        {
            var bytes = Hex.ToBytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
            var bestMatch = XorBreaker.BestMatch(bytes).First();
            var plainText = Encoding.UTF8.GetString(Xor.ApplyRepeating(bytes, new [] {bestMatch.key}));

            Assert.Equal("Cooking MC's like a pound of bacon", plainText);
        }

        /*
        Detect single-character XOR

        One of the 60-character strings in 4.txt file has been encrypted by single-character XOR.

        Find it.

        (Your code from #3 should help.)
        */
        [Fact]
        public void Challenge04_FindXORInFile()
        {
            var lines      = File.ReadAllLines("Data/4.txt");
            var candidates = new List<(string line, byte key, double score)>(lines.Length);
            foreach (var line in lines)
            {
                var c = XorBreaker.BestMatch(Hex.ToBytes(line)).First();
                candidates.Add((line, c.key, c.score));
            }

            var candidate = candidates.OrderByDescending(x => x.score).First();
            var plainText = Encoding.UTF8.GetString(Xor.ApplyRepeating(Hex.ToBytes(candidate.line), new [] { candidate.key }));
            Assert.Equal("Now that the party is jumping\n", plainText);
        }

        /*
        Implement repeating-key XOR

        Here is the opening stanza of an important work of the English language:

        ```
        Burning 'em, if you ain't quick and nimble
        I go crazy when I hear a cymbal
        ```

        Encrypt it, under the key "ICE", using repeating-key XOR.

        In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I,
        the next C, the next E, then I again for the 4th byte, and so on.

        It should come out to:

        0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
        a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

        Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file.
        Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.
        */
        [Fact]
        public void Challenge05_RepeatingXOR()
        {
            Assert.Equal("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
                         Hex.ToString(Xor.ApplyRepeating(Encoding.UTF8.GetBytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"), Encoding.UTF8.GetBytes("ICE"))));
        }

        /*
        Break repeating-key XOR

        It is officially on, now.
        This challenge isn't conceptually hard, but it involves actual error-prone coding.
        The other challenges in this set are there to bring you up to speed.
        This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

        There's a file 6.txt. It's been base64'd after being encrypted with repeating-key XOR.

        Decrypt it.

        Here's how:

            1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

            2. Write a function to compute the edit distance/Hamming distance between two strings.
               The Hamming distance is just the number of differing bits. The distance between:

               this is a test

               and

               wokka wokka!!!

               is 37. Make sure your code agrees before you proceed.

            3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
               and find the edit distance between them. Normalize this result by dividing by KEYSIZE.

            4. The KEYSIZE with the smallest normalized edit distance is probably the key.
               You could proceed perhaps with the smallest 2-3 KEYSIZE values.
               Or take 4 KEYSIZE blocks instead of 2 and average the distances.

            5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.

            6. Now transpose the blocks: make a block that is the first byte of every block,
               and a block that is the second byte of every block, and so on.

            7. Solve each block as if it was single-character XOR. You already have code to do this.

            8. For each block, the single-byte XOR key that produces the best looking histogram
               is the repeating-key XOR key byte for that block. Put them together and you have the key.
        
        This code is going to turn out to be surprisingly useful later on.
        Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing.
        But more people "know how" to break it than can actually break it,
        and a similar technique breaks something much more important.

        No, that's not a mistake.
        We get more tech support questions for this challenge than any of the other ones.
        We promise, there aren't any blatant errors in this text. In particular: the "wokka wokka!!!" edit distance really is 37.
        */
        [Fact]
        public void Challenge06_BreakRepeatingXOR()
        {
            Assert.Equal(37u, Hamming.GetDistance(Encoding.UTF8.GetBytes("this is a test"), Encoding.UTF8.GetBytes("wokka wokka!!!")));

            var base64 = File.ReadAllText("Data/6.txt").Replace("\n", "");
            var cipher = Convert.FromBase64String(base64);

            var len = XorBreaker.GuessRepeatingKeyLength(cipher, 40);
            var key = XorBreaker.BreakRepeating(cipher, len);

            Assert.Equal("Terminator X: Bring the noise", Encoding.UTF8.GetString(key));
            Assert.StartsWith("I'm back and I'm ringin' the bell ", Encoding.UTF8.GetString(Xor.ApplyRepeating(cipher, key)));
        }

        /*
        AES in ECB mode

        The Base64-encoded content in 7.tx file has been encrypted via AES-128 in ECB mode under the key

        "YELLOW SUBMARINE".

        (case-sensitive, without the quotes; exactly 16 characters;
        I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

        Decrypt it. You know the key, after all.

        Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

        Do this with code.
        You can obviously decrypt this using the OpenSSL command-line tool,
        but we're having you get ECB working in code for a reason.
        You'll need it a lot later on, and not just for attacking ECB.
        */
        [Fact]
        public void Challenge07_DecryptAesEcb()
        {
            var base64 = File.ReadAllText("Data/7.txt").Replace("\n", "");
            var cipher = Convert.FromBase64String(base64);
            Assert.Equal("I'm back and I'm ringin' the bell ",
                         Encoding.UTF8.GetString(MyAes.DecryptEcb(cipher,
                                                                  Encoding.UTF8.GetBytes("YELLOW SUBMARINE"))).Split('\n')[0]);
        }

        /*
        Detect AES in ECB mode

        In 8.txt file are a bunch of hex-encoded ciphertexts.

        One of them has been encrypted with ECB.

        Detect it.

        Remember that the problem with ECB is that it is stateless and deterministic;
        the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
        */
        [Fact]
        public void Challenge08_DetectEcb()
        {
            var lines      = File.ReadAllLines("Data/8.txt");
            var candidates = new Dictionary<int, int>(lines.Length);

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
