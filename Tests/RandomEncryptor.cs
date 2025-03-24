using System;
using System.Security.Cryptography;
using MyCrypto;

namespace Tests
{
    public static class RandomEncryptor
    {
        public static (byte[] cipher, CipherMode mode) Encrypt(ReadOnlySpan<byte> plainText)
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                var key = new byte[16];
                rnd.GetBytes(key);

                var before = new byte[rnd.GetInt(5, 10)];
                rnd.GetBytes(before);

                var after = new byte[rnd.GetInt(5, 10)];
                rnd.GetBytes(after);

                var appended = new byte[before.Length + plainText.Length + after.Length];
                Array.Copy(before, appended, before.Length);
                plainText.CopyTo(appended.AsSpan(before.Length));
                Array.Copy(after, 0, appended, before.Length + plainText.Length, after.Length);

                var m = rnd.GetInt(0, 1);
                var mode = m % 2 == 0 ? CipherMode.CBC : CipherMode.ECB;
                if (mode == CipherMode.CBC)
                {
                    var iv = new byte[16];
                    rnd.GetBytes(iv);
                    return (MyAes.EncryptCbcPkcs7(appended, iv, key), mode);
                }
                else
                {
                    return (MyAes.EncryptEcb(appended, key), mode);
                }
            }
        }
    }
}
