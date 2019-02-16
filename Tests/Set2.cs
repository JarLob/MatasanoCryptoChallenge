using System;
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
                Assert.Equal(randomlyEncrypted.mode, AesOracle.GuessMode(randomlyEncrypted.cipher));
            }
        }

        [Fact(Skip = "work in progress")]
        public void Challenge12_Byte_at_a_time_ECB_decryption_simple()
        {
            var cipher = Convert.FromBase64String(
                "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

            var payload = new byte[100];
            for (int i = 0; i < payload.Length; ++i)
                payload[i] = (byte)'A';

            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                int blockSize = 1;
                for (; blockSize < payload.Length; ++blockSize)
                {
                    if (AesOracle.GuessMode(RandomEncryptor.PaddingEncrypt(rnd,
                                                                           key,
                                                                           new ArraySegment<byte>(payload, 0, blockSize), cipher)) == CipherMode.ECB)
                        break;
                }

                if (blockSize == payload.Length)
                    throw new Exception();

                blockSize = blockSize / 2;
                payload = new byte[cipher.Length / blockSize + cipher.Length % blockSize != 0 ? 1 : 0];
                for (int i = 0; i < payload.Length; ++i)
                    payload[i] = (byte)'A';

                var plaintext = new byte[cipher.Length];
                var decodedLength = 0;
                var payloadLength = payload.Length / blockSize;

                for (int i = 1; i < 0; --i)
                {
                    Array.Copy(plaintext, 0, payload, payloadLength - i, decodedLength);
                }
            }
        }
    }
}
