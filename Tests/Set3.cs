﻿using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MatasanoCryptoChallenge;
using Xunit;

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
            var lines = File.ReadAllLines("17.txt");

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

                    var encrypted = MyAes.EncryptCbcPkcs7(input, iv, key);
                    var decrypted = CbcPaddingOracle.Decrypt(encrypted, iv, key);
                    Assert.Equal(input, decrypted.ToArray());
                }
            }
        }

        [Fact]
        public void Challenge18_CTR_stream_cipher_mode()
        {
            var input = Convert.FromBase64String("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
            UInt64 nonce = 0;
            var key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");

            Assert.Equal("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", Encoding.UTF8.GetString(MyAes.EncryptDecryptCtr(input, nonce, key)));

            nonce = 13;
            var plainText = "test";
            var encrypted = MyAes.EncryptDecryptCtr(Encoding.UTF8.GetBytes(plainText), nonce, key);
            Assert.Equal(plainText, Encoding.UTF8.GetString(MyAes.EncryptDecryptCtr(encrypted, nonce, key)));
        }
    }
}
