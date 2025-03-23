using System;

namespace MatasanoCryptoChallenge
{
    public static class Bit
    {
        public static byte GetCount(ulong value)
        {
            var result = value - ((value >> 1) & 0x5555555555555555UL);
            result = (result & 0x3333333333333333UL) + ((result >> 2) & 0x3333333333333333UL);
            return (byte)(unchecked(((result + (result >> 4)) & 0xF0F0F0F0F0F0F0FUL) * 0x101010101010101UL) >> 56);
        }

        public static byte GetCount(uint value)
        {
            var result = value - ((value >> 1) & 0x55555555);
            result = (result & 0x33333333) + ((result >> 2) & 0x33333333);
            return (byte)(unchecked(((result + (result >> 4)) & 0xF0F0F0F) * 0x1010101) >> 24);
        }

        public static byte GetCount(byte value)
        {
            byte count = 0;
            for (; value != 0; ++count)
            {
                value &= (byte)(value - 1);
            }

            return count;
        }

        public static bool Get(uint value, int index)
        {
            if (index < 0 || index > 31)
                throw new Exception();

            value = value >> (31 - index);
            return (value & 1U) != 0U;
        }

        public static void Set(ref uint integer, int index, bool bit)
        {
            if (index < 0 || index > 31)
                throw new Exception();

            if (bit)
                integer = integer | (1U << (31 - index));
            else
                integer &= ~(1U << (31 - index));
        }
    }
}
