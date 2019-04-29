using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MatasanoCryptoChallenge;
using Xunit;

namespace Tests
{
    public class Set2
    {
        [Fact]
        public void Challenge09_PKCS7()
        {
            Assert.Equal("YELLOW SUBMARINE\x04\x04\x04\x04", Encoding.UTF8.GetString(PKCS7.Pad(Encoding.UTF8.GetBytes("YELLOW SUBMARINE"), 20)));
        }

        [Fact]
        public void Challenge10_CBCMode()
        {
            var data = Encoding.UTF8.GetBytes("test");
            byte[] cipher;
            byte[] decrypted;
            byte[] key = Encoding.UTF8.GetBytes("ss012345678901234567890123456789");
            byte[] iv = new byte[16];

            cipher = MyAes.Encrypt(data, key, CipherMode.CBC);

            using (var aes2 = new AesCryptoServiceProvider())
            {
                aes2.Key = key;
                aes2.IV = iv;
                using (var dec = aes2.CreateDecryptor())
                    decrypted = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            }

            Assert.Equal(data, decrypted);

            cipher = Convert.FromBase64String(File.ReadAllText("10.txt"));
            using (var aes2 = new AesCryptoServiceProvider())
            {
                aes2.Key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
                aes2.IV  = iv;
                using (var dec = aes2.CreateDecryptor())
                    decrypted = dec.TransformFinalBlock(cipher, 0, cipher.Length);

                var text = Encoding.UTF8.GetString(decrypted);
                Assert.StartsWith("I'm back and I'm ringin' the bell ", text);
            }

        }

        [Fact]
        public void Challenge11_ECB_CBC_DetectionOracle()
        {
            int size = 16 * 3;
            var payload = new byte[size];

            for (int i = 0; i < 100; ++i)
            {
                var randomlyEncrypted = RandomEncryptor.Encrypt(payload);
                Assert.Equal(0, randomlyEncrypted.cipher.Length % 16);
                Assert.Equal(randomlyEncrypted.mode, AesOracle.GuessMode(randomlyEncrypted.cipher, 16));
            }
        }

        [Fact]
        public void Challenge12_Byte_at_a_time_ECB_decryption_simple()
        {
            var secretSuffix = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                Func<ArraySegment<byte>, byte[]> encrypt = data => MyAes.Encrypt(data, secretSuffix, key);

                var blockSize = AesOracle.GuessBlockSize(encrypt);
                Assert.Equal(16, blockSize);

                var payload = new byte[3 * blockSize];
                var encrypted = encrypt(payload);
                Assert.Equal(CipherMode.ECB, AesOracle.GuessMode(encrypted, blockSize));

                var calculatedPrefixLength = AesOracle.GetPrefixLength(blockSize, encrypt);
                Assert.Equal(0, calculatedPrefixLength);

                var decrypted = AesOracle.ByteAtATimeEcb(blockSize, encrypt);
                var plainText = Encoding.UTF8.GetString(decrypted);
                var secretText = Encoding.UTF8.GetString(secretSuffix);
                Assert.Equal(secretText, plainText);
            }
        }

        [Fact]
        public void Challenge13_ECB_cut_and_paste()
        {
            var textQuery = "foo=bar&baz=qux&zap=zazzle";
            var query     = HttpQuery.Parse(textQuery);
            Assert.Equal(query, new[]
            {
                ("foo", "bar"),
                ("baz", "qux"),
                ("zap", "zazzle")
            });

            Assert.Equal(HttpQuery.Compile(query), textQuery);

            var oracle = new UserProfileOracle();
            var cipher = oracle.CreateFor("test@test.com");
            Assert.Equal("test@test.com", oracle.Decrypt(cipher).First().value);

            var cipher1 = oracle.CreateFor("foo22@bar.com");
            var cipher2 = oracle.CreateFor("          admin\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb\xb");
            cipher = new byte[16 * 3];
            Array.Copy(cipher1, cipher, 16 * 2);
            Array.Copy(cipher2, 16, cipher, 16 * 2, 16);
            Assert.Equal("admin", oracle.Decrypt(cipher).Last().value);
            Assert.Equal("foo22@bar.com", oracle.Decrypt(cipher).First().value);
        }

        [Fact]
        public void Challenge14_Byte_at_a_time_ECB_decryption_harder()
        {
            var secretSuffix = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                var prefixLength = rnd.GetInt(0, 256);
                Assert.True(prefixLength >= 0);
                var prefix = new byte[prefixLength];
                rnd.GetBytes(prefix);

                Func<ArraySegment<byte>, byte[]> encrypt = data => MyAes.Encrypt(prefix, data, secretSuffix, key);

                var blockSize = AesOracle.GuessBlockSize(encrypt);
                Assert.Equal(16, blockSize);

                var payload = new byte[3 * blockSize];
                var encrypted = encrypt(payload);
                Assert.Equal(CipherMode.ECB, AesOracle.GuessMode(encrypted, blockSize));

                var calculatedPrefixLength = AesOracle.GetPrefixLength(blockSize, encrypt);
                Assert.Equal(prefixLength, calculatedPrefixLength);

                var decrypted = AesOracle.ByteAtATimeEcb(blockSize, encrypt, calculatedPrefixLength);
                var plainText = Encoding.UTF8.GetString(decrypted);
                var secretText = Encoding.UTF8.GetString(secretSuffix);
                Assert.Equal(secretText, plainText);
            }
        }
    }
}
