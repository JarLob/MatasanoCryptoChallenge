using System;
using System.Security.Cryptography;
using MyCrypto;

namespace MatasanoCryptoChallenge
{
    public static class CbcPaddingOracle
    {
        public static ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encrypted,
                                                 Func<ReadOnlySpan<byte>, ReadOnlySpan<byte>, bool> validateOracle,
                                                 ReadOnlySpan<byte> iv = default)                                  
        {
            if (encrypted.Length % 16 != 0)
                throw new Exception();

            var decrypted = new byte[encrypted.Length];
            Span<byte> fakeEncrypted = new byte[16*2];

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block >= 0; --block)
            {
                ReadOnlySpan<byte> realPrevBlock;
                if (block == 0)
                    realPrevBlock = iv.IsEmpty ? new byte[16] : iv;
                else
                    realPrevBlock = encrypted.Slice((block - 1) * 16, 16);

                Span<byte> fakePrevBlock = new byte[16];
                for (int i = 15; i >= 0; --i)
                {
                    realPrevBlock.CopyTo(fakePrevBlock);
                    byte desiredPaddingValue = (byte)(16 - i);

                    // set bytes past the current index to produce needed padding as
                    // "0x02" or "0x03 0x03" or "0x04 0x04 0x04" etc.
                    // by using already decrypted values
                    for (int n = 15; n > i; --n)
                    {
                        fakePrevBlock[n] = (byte)(realPrevBlock[n] ^ decrypted[block * 16 + n] ^ desiredPaddingValue);
                    }

                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("Unexpected: the byte wasn't found");

                        fakePrevBlock[i] = (byte)b;
                        fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                        encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                        if (validateOracle(fakeEncrypted, iv))
                        {
                            // once we have decrypted the last byte and desiredPaddingValue != 1 we force the padding value above
                            // so we don't need the check
                            if (i != 0 && desiredPaddingValue == 1)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02" or "0x03 0x03 0x03" or etc.
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                fakePrevBlock[i - 1] += 1;
                                fakePrevBlock.CopyTo(fakeEncrypted.Slice(0, 16));
                                encrypted.Slice(block * 16, 16).CopyTo(fakeEncrypted.Slice(16, 16));
                                if (!validateOracle(fakeEncrypted, iv))
                                    continue;
                            }

                            // At this point we know that b XOR D(encrypted) = desiredPaddingValue
                            // However the real plaintext = realPrevBlock[i] XOR D(encrypted)
                            // From two equations above: D(encrypted) = desiredPaddingValue XOR b = plaintext XOR realPrevBlock[i]
                            decrypted[block * 16 + i] = (byte)(b ^ desiredPaddingValue ^ realPrevBlock[i]);
                            break;
                        }
                    }
                }
            }

            return PKCS7.StripPad(decrypted);
        }

        public static ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> payload, Func<ReadOnlySpan<byte>, bool> validateOracle)
        {
            ReadOnlySpan<byte> payloadPadded = PKCS7.Pad(payload, 16).AsSpan();
            var encrypted = new byte[16 + payloadPadded.Length];

            using (var rnd = RandomNumberGenerator.Create())
            {
                // the last block is of our choice and could be constant
                // but since we don't know the IV and produce a garbage block
                // the decrypted value may cause parsing errors
                // it is better to randomize it every time
                rnd.GetBytes(encrypted.AsSpan(encrypted.Length - 16));
            }

            var blocks = encrypted.Length / 16;
            for (int block = blocks - 1; block > 0; --block)
            {
                for (int i = 15; i >= 0; --i)
                {
                    byte desiredPaddingValue = (byte)(16 - i);
                    var twoBlocks = encrypted.AsSpan((block - 1) * 16, 32);
                    for (int b = 0; b <= 256; ++b)
                    {
                        if (b == 256)
                            throw new Exception("Unexpected: the byte wasn't found");

                        twoBlocks[i] = (byte)b;
                        if (validateOracle(twoBlocks))
                        {
                            if (i != 0 && desiredPaddingValue == 1)
                            {
                                // We are looking for "0xAny 0x01" padding
                                // But may accidentally find "0x02 0x02" or "0x03 0x03 0x03" or etc.
                                // Let's modify i - 1 byte. If the first case the byte is not used for padding and doesn't affect validation
                                twoBlocks[i - 1] += 1;
                                if (!validateOracle(twoBlocks))
                                    continue;
                            }

                            for (int j = 15; j >= i; --j)
                            {
                                // We know that the decrypted and xored value is of valid padding
                                // Xor it again with the padding value to calculate values that produce Zeroes instead of the padding
                                // Zeros will be conveniet later for xoring with the payload
                                twoBlocks[j] = (byte)(twoBlocks[j] ^ desiredPaddingValue);
                                if (desiredPaddingValue < 16)
                                    // calculate values for the next round: Xor it again with the next padding value
                                    twoBlocks[j] = (byte)(twoBlocks[j] ^ (desiredPaddingValue + 1));
                            }
                            break;
                        }
                    }
                }

                var c = encrypted.AsSpan((block - 1) * 16, 16);
                var p = payloadPadded.Slice((block - 1) * 16, 16);
                for (int j = 15; j >= 0; --j)
                    // The calculated values in the block will produce zeroes when xored with the next decrypted block
                    // Just xor them with desiried payload
                    c[j] = (byte)(c[j] ^ p[j]);
            }

            return encrypted;
        }
    }
}
