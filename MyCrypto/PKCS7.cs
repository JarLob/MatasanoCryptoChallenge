using System.Security.Cryptography;

namespace MyCrypto
{
    public static class PKCS7
    {
        public static byte[] Pad(ReadOnlySpan<byte> data, byte blockSize)
        {
            byte mod = (byte)(data.Length % blockSize);
            byte padSize = mod == 0 ? blockSize : (byte)(blockSize - mod);
            var output = new byte[data.Length + padSize];
            data.CopyTo(output);

            for (int i = data.Length; i < output.Length; ++i)
            {
                output[i] = padSize;
            }
            return output;
        }

        public static ReadOnlySpan<byte> StripPad(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
                throw new Exception();

            var pads = data[data.Length - 1];
            if (pads < 1 || pads > data.Length)
                throw new CryptographicException("Padding is invalid and cannot be removed.");

            for (int i = 1; i < pads; ++i)
            {
                if (data[data.Length - i - 1] != pads)
                    throw new CryptographicException("Padding is invalid and cannot be removed.");
            }

            return data.Slice(0, data.Length - pads);
        }
    }
}
