namespace MyCrypto
{
    public static class Xor
    {
        public static byte[] ApplyFixed(ReadOnlySpan<byte> bytesData, ReadOnlySpan<byte> bytesKey)
        {
            if (bytesData.Length != bytesKey.Length)
                throw new Exception();

            var output = new byte[bytesData.Length];
            for (var i = 0; i < bytesData.Length; i++)
            {
                output[i] = (byte)(bytesData[i] ^ bytesKey[i]);
            }

            return output;
        }

        public static byte[] ApplyRepeating(ReadOnlySpan<byte> bytesData, ReadOnlySpan<byte> bytesKey)
        {
            int k = 0;
            var output = new byte[bytesData.Length];
            for (var i = 0; i < bytesData.Length; i++)
            {
                output[i] = (byte)(bytesData[i] ^ bytesKey[k]);
                if (++k == bytesKey.Length)
                    k = 0;
            }

            return output;
        }
    }
}
