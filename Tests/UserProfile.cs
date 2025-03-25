using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using MyCrypto;

namespace Tests
{
    internal class UserProfile
    {
        private readonly byte[] Key;

        public UserProfile()
        {
            using (var rnd = RandomNumberGenerator.Create())
            {
                Key = new byte[16];
                rnd.GetBytes(Key);
            }
        }

        public byte[] CreateFor(string email)
        {
            if (email.Any(x => x == '&' || x == '='))
                throw new Exception();

            var obj = new List<(string key, string value)>(3)
            {
                ("email", email),
                ("uid", "10"),
                ("role", "user")
            };

            return MyAes.EncryptEcb(Encoding.UTF8.GetBytes(HttpQuery.Compile(obj)), Key);
        }

        public List<(string key, string value)> Decrypt(ReadOnlySpan<byte> cipher)
        {
            var plainText = Encoding.UTF8.GetString(MyAes.DecryptEcb(cipher, Key));
            return HttpQuery.Parse(plainText);
        }
    }
}
