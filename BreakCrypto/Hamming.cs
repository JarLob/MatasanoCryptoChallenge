using System;

namespace MatasanoCryptoChallenge
{
    public static class Hamming
    {
        public static uint GetDistance(ReadOnlySpan<byte> xArray, ReadOnlySpan<byte> yArray)
        {
            if (xArray.Length != yArray.Length)
                throw new Exception();

            uint count = 0;
            int i = 0;

            unsafe
            {
                fixed (byte* pX = xArray, pY = yArray)
                {
                    for (; i + sizeof(ulong) < xArray.Length; i += sizeof(ulong))
                    {
                        var diff = *(ulong*)&pX[i] ^ *(ulong*)&pY[i];
                        count += Bit.GetCount(diff);
                    }

                    for (; i + sizeof(uint) < xArray.Length; i += sizeof(uint))
                    {
                        var diff = *(uint*)&pX[i] ^ *(uint*)&pY[i];
                        count += Bit.GetCount(diff);
                    }
                }
            }

            for (; i < xArray.Length; ++i)
            {
                var diff = (byte)(xArray[i] ^ yArray[i]);
                count += Bit.GetCount(diff);
            }

            return count;
        }
    }
}
