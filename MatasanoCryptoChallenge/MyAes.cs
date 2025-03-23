using System;
using System.Security.Cryptography;

namespace MatasanoCryptoChallenge
{
    public static class MyAes
    {
        public static byte[] EncryptDecryptCtr(ReadOnlySpan<byte> data, ulong nonce, byte[] key)
        {
            var nonceBytes = BitConverter.GetBytes(nonce);
            if (!BitConverter.IsLittleEndian)
                Array.Reverse(nonceBytes);

            var blocks = data.Length / 16 + (data.Length % 16 > 0 ? 1 : 0);
            var output = new byte[data.Length];
            var nonceAndCounter = new byte[16];
            nonceBytes.CopyTo(nonceAndCounter, 0);

            for (int i = 0; i < blocks; ++i)
            {
                var counterBytes = BitConverter.GetBytes((ulong)i);
                if (!BitConverter.IsLittleEndian)
                    Array.Reverse(counterBytes);

                counterBytes.CopyTo(nonceAndCounter, 8);
                var decryptedBlock = EncryptEcb(nonceAndCounter, key, PaddingMode.None);

                var oMax = Math.Min(i * 16 + 16, data.Length);
                for (int o = i * 16, d = 0; o < oMax; ++o, ++d)
                {
                    output[o] = (byte)(decryptedBlock[d] ^ data[o]);
                }
            }

            return output;
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> data, ReadOnlySpan<byte> dataSuffix, byte[] key)
        {
            var appended = new byte[data.Length + dataSuffix.Length];
            data.CopyTo(appended);
            dataSuffix.CopyTo(appended.AsSpan(data.Length));
            return EncryptEcb(appended, key);
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> dataPrefix, ReadOnlySpan<byte> data, ReadOnlySpan<byte> dataSuffix, byte[] key)
        {
            var appended = new byte[dataPrefix.Length + data.Length + dataSuffix.Length];
            dataPrefix.CopyTo(appended);
            data.CopyTo(appended.AsSpan(dataPrefix.Length));
            dataSuffix.CopyTo(appended.AsSpan(dataPrefix.Length + data.Length));
            return EncryptEcb(appended, key);
        }

        public static byte[] EncryptEcb(ReadOnlySpan<byte> data, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return EncryptEcb(data.ToArray(), key, padding);
        }

        public static byte[] EncryptEcb(byte[] data, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return _LibraryEncrypt(data, null, key, CipherMode.ECB, padding);
        }

        public static byte[] _LibraryEncrypt(byte[] data, byte[] iv, byte[] key, CipherMode mode, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key     = key;
                aes.Mode    = mode;
                aes.Padding = padding;

                if (aes.Mode == CipherMode.CBC)
                {
                    if (iv == default)
                        throw new Exception();

                    aes.IV = iv;
                }

                using (var encr = aes.CreateEncryptor())
                {
                    var text = encr.TransformFinalBlock(data, 0, data.Length);
                    return text;
                }
            }
        }

        public static byte[] DecryptEcb(ReadOnlySpan<byte> cipher, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return DecryptEcb(cipher.ToArray(), key, padding);
        }

        public static byte[] DecryptEcb(byte[] cipher, byte[] key, PaddingMode padding = PaddingMode.PKCS7)
        {
            return _LibraryDecrypt(cipher, null, key, CipherMode.ECB, padding);
        }

        public static byte[] EncryptCbcPkcs7(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, byte[] key)
        {
            return _CustomEncryptCbcPkcs7(data, iv, key);
        }

        public static byte[] EncryptCbcPkcs7(byte[] data, byte[] iv, byte[] key)
        {
            return _CustomEncryptCbcPkcs7(data, iv, key);
        }

        public static byte[] _CustomEncryptCbcPkcs7(ReadOnlySpan<byte> data, ReadOnlySpan<byte> iv, byte[] key)
        {
            var len       = data.Length  / 16 + 1;
            var output    = new byte[len * 16];
            var prevBlock = iv;
            int i         = 0;
            for (; i < len - 1; i++)
            {
                var xored     = Xor.ApplyFixed(prevBlock, data.Slice(i * 16, 16));
                var encrypted = EncryptEcb(xored, key, PaddingMode.None);
                Array.Copy(encrypted, 0, output, i * 16, 16);
                prevBlock = encrypted;
            }

            var padded = PKCS7.Pad(data.Slice(i * 16, data.Length % 16), 16);
            Array.Copy(EncryptEcb(Xor.ApplyFixed(prevBlock, padded), key), 0, output, i * 16, 16);
            return output;
        }

        public static ReadOnlySpan<byte> DecryptCbcPkcs7(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> iv, byte[] key)
        {
            return _CustomDecryptCbcPkcs7(cipher, iv, key);
            //return _LibraryDecrypt(cipher.ToArray(), iv.ToArray(), key, CipherMode.CBC);
        }

        public static ReadOnlySpan<byte> DecryptCbcPkcs7(byte[] cipher, byte[] iv, byte[] key)
        {
            return _CustomDecryptCbcPkcs7(cipher, iv, key);
            //return _LibraryDecrypt(cipher, iv, key, CipherMode.CBC);
        }

        public static ReadOnlySpan<byte> _CustomDecryptCbcPkcs7(ReadOnlySpan<byte> cipher, ReadOnlySpan<byte> iv, byte[] key)
        {
            var blocks = cipher.Length / 16;
            var output = new byte[cipher.Length];
            for (int i = blocks - 1; i >= 0; --i)
            {
                ReadOnlySpan<byte> prevBlock;
                if (i == 0)
                    prevBlock = iv;
                else
                    prevBlock = cipher.Slice((i - 1) * 16, 16);

                var decryptedBlock = DecryptEcb(cipher.Slice(i * 16, 16), key, PaddingMode.None);
                var xored          = Xor.ApplyFixed(prevBlock, decryptedBlock);
                Array.Copy(xored, 0, output, i * 16, 16);
            }

            return PKCS7.StripPad(output);
        }

        public static byte[] _LibraryDecrypt(byte[] cipher, byte[] iv, byte[] key, CipherMode mode, PaddingMode padding = PaddingMode.PKCS7)
        {
            using (var aes = Aes.Create())
            {
                aes.Key     = key;
                aes.Mode    = mode;
                aes.Padding = padding;

                if (aes.Mode == CipherMode.CBC)
                {
                    if (iv == default)
                        throw new Exception();

                    aes.IV = iv;
                }

                using (var decr = aes.CreateDecryptor())
                {
                    var text = decr.TransformFinalBlock(cipher, 0, cipher.Length);
                    return text;
                }
            }
        }
    }
}
