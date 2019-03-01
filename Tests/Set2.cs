using System;
using System.IO;
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
            for (int i = 0; i < size; ++i)
                payload[i] = (byte)'A';

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

                var blockSize = AesOracle.GuessBlockSize(data => MyAes.PaddingEncrypt(rnd, key, data, secretSuffix));
                Assert.Equal(16, blockSize);

                var payload = new byte[3 * blockSize];
                for (int i = 0; i < payload.Length; ++i)
                    payload[i] = (byte)'A';

                var encrypted = MyAes.PaddingEncrypt(rnd, key, payload, secretSuffix);
                Assert.Equal(CipherMode.ECB, AesOracle.GuessMode(encrypted, blockSize));

                var decrypted = AesOracle.ByteAtATimeEcb(blockSize, data => MyAes.PaddingEncrypt(rnd, key, data, secretSuffix));
                var plainText = Encoding.UTF8.GetString(decrypted);
                var secretText = Encoding.UTF8.GetString(secretSuffix);
                Assert.Equal(secretText, plainText);
            }
        }
    }
}
