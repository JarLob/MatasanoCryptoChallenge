using System;
using System.Security.Cryptography;

namespace MatasanoCryptoChallenge
{
    public static class CryptoRandom
    {
        public static int GetInt(this RandomNumberGenerator rng)
        {
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            return BitConverter.ToInt32(bytes, 0) & 0x7FFFFFFF;
        }

        public static int GetInt(this RandomNumberGenerator rng, int maxValue)
        {
            if (maxValue < 0)
                throw new ArgumentOutOfRangeException("maxValue");

            return GetInt(rng, 0, maxValue);
        }

        public static int GetInt(this RandomNumberGenerator rng, int minValue, int maxValue)
        {
            if (minValue > maxValue)
                throw new ArgumentOutOfRangeException("minValue");

            if (minValue == maxValue)
                return minValue;

            long diff = maxValue - minValue + 1;
            var bytes = new byte[4];

            long max = (1 + (long)UInt32.MaxValue);
            long remainder = max % diff;

            while (true)
            {
                rng.GetBytes(bytes);
                var rand = BitConverter.ToUInt32(bytes, 0);

                if (rand < max - remainder)
                {
                    return (Int32)(minValue + (rand % diff));
                }
            }
        }

        public static double GetDouble(this RandomNumberGenerator rng)
        {
            var bytes = new byte[4];
            rng.GetBytes(bytes);
            var rand = BitConverter.ToUInt32(bytes, 0);
            return rand / (1.0 + UInt32.MaxValue);
        }
    }
}
