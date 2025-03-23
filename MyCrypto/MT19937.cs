namespace MyCrypto
{
    public class MT19937
    {
        private const uint w = 32U, n = 624U, m = 397U, r = 31U, f = 1812433253U;

        private const int u = 11, s = 7, t = 15, l = 18;

        private const uint d = 0xFFFFFFFFU, a = 0x9908B0DFU, b = 0x9D2C5680U, c = 0xEFC60000U;

        private readonly uint[] MT = new uint[n]; // Create a length n array to store the state of the generator

        private uint index = n + 1;

        private const uint lower_mask = unchecked((1 << (int)r) - 1); // That is, the binary number of r 1's
        private const uint upper_mask = ~lower_mask & 0xffffffffU; // lowest w bits of (not lower_mask)

        public MT19937(IEnumerable<uint> MT)
        {
            var mt = MT.ToArray();
            if (mt.Length != 624)
                throw new Exception();

            this.MT = mt;
            index = n;
        }

        public MT19937()
        {
        }

        // Initialize the generator from a seed
        public void SeedMt(uint seed)
        {
            index = n;
            MT[0] = seed;

            for (int i = 1; i < MT.Length; ++i)
                MT[i] = (uint)(0xffffffffU & (f * (MT[i - 1] ^ (MT[i - 1] >> (int)(w - 2))) + i));
        }

        // Extract a tempered value based on MT[index]
        // calling twist() every n numbers
        public uint ExtractNumber()
        {
            if (index >= n)
            {
                if (index > n)
                {
                    throw new Exception("Generator was never seeded");
                    // Alternatively, seed with constant value; 5489 is used in reference C code[46]
                }
                Twist();
            }

            uint y = MT[index++];
            return Temper(y);
        }

        private static uint Temper(uint y)
        {
            y = y ^ ((y >> u) & d);
            y = y ^ ((y << s) & b);
            y = y ^ ((y << t) & c);
            y = y ^ (y >> l);
            return y;
        }

        // Generate the next n values from the series x_i
        private void Twist()
        {
            for (int i = 0; i < n; ++i)
            {
                uint x = (MT[i] & upper_mask) + (MT[(i + 1) % n] & lower_mask);
                uint xA = x >> 1;

                if ((x % 2) != 0)
                {
                    // lowest bit of x is 1
                    xA = xA ^ a;
                }
                MT[i] = MT[(i + m) % n] ^ xA;
            }
            index = 0;
        }
    }
}
