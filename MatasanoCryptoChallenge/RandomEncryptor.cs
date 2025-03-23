using System;
using System.Security.Cryptography;

namespace MatasanoCryptoChallenge
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
                return (mode == CipherMode.CBC ? MyAes.EncryptCbcPkcs7(appended, IV, key) : MyAes.EncryptEcb(appended, key), mode);
            }
        }

        private static readonly byte[] IV = new byte[16];
    }
}
