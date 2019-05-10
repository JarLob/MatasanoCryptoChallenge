﻿using System;
using System.IO;
using System.Security.Cryptography;
using MatasanoCryptoChallenge;
using Xunit;

namespace Tests
{
    public class Set3
    {
        [Fact]
        public void Challenge17_CBC_padding_oracle()
        {
            var lines = File.ReadAllLines("17.txt");

            using (var rnd = RandomNumberGenerator.Create())
            {
                var input = Convert.FromBase64String(lines[rnd.GetInt(0, lines.Length)]);

                var key = new byte[16];
                rnd.GetBytes(key);

                var iv = new byte[16];
                rnd.GetBytes(iv);

                var encrypted = MyAes.Encrypt(input, iv, key, CipherMode.CBC);
                var decrypted = MyAes.DecryptCBCWithPadding(encrypted, iv, key);
                Assert.Equal(input, decrypted.ToArray());

                decrypted = CbcPaddingOracle.Decrypt(encrypted, iv, key);
                Assert.Equal(input, decrypted.ToArray());
            }
        }
    }
}