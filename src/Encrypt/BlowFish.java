package Encrypt;

import java.io.UnsupportedEncodingException;

class BlowFish {

    private long xl;
    private long xr;
    private int N = 16;
    private int ROUNDS = 16;
    private long[] pi = new long[N + 2];
    private long[][] si = new long[4][256];
    private static final long modulus = (long) Math.pow(2L, 32);

    BlowFish(byte[] key) throws UnsupportedEncodingException {
        if (key.length > 56)
            throw new ArrayIndexOutOfBoundsException("Key must be less than 56 symbols!");
        else if (key.length < 4)
            throw new StringIndexOutOfBoundsException("Key must be greater than 4 symbols!");

        System.arraycopy(RandomNumberTables.bf_P, 0, pi, 0, N + 2);
        for (int i = 0; i < 4; i++)
            System.arraycopy(RandomNumberTables.bf_S[i], 0, si[i], 0, 256);

        setupKey(key, key.length);
    }

    private void setupKey(byte[] key, int length) {
        int j = 0;
        for (int i = 0; i < N + 2; i++) {
            pi[i] &= 0xffffffffL;
            pi[i] ^= key[j];
            j = (j + 1) % length;
        }
        for (int i = 0; i < N + 2; i += 2) {
            encipher();
            pi[i] = xl;
            pi[i + 1] = xr;
        }
        for (int i = 0; i < 4; i++) {
            for (int k = 0; k < 256; k += 2) {
                encipher();
                si[i][k] = xl;
                si[i][k + 1] = xr;
            }
        }
    }

    private void encipher() {
        xl = xor(xl, pi[0]);

        for (int i = 0; i < ROUNDS; i += 2) {
            xr = xor(xr, xor(F(xl), pi[i + 1]));
            xl = xor(xl, xor(F(xr), pi[i + 2]));
        }

        xr = xor(xr, pi[ROUNDS + 1]);

        long temp;
        temp = xl;
        xl = xr;
        xr = temp;
    }

    private void decipher() {
        xl = xor(xl, pi[ROUNDS + 1]);

        for (int i = ROUNDS; i > 0; i -= 2) {
            xr = xor(xr, xor(F(xl), pi[i]));
            xl = xor(xl, xor(F(xr), pi[i - 1]));
        }

        xr = xor(xr, pi[0]);

        long temp;
        temp = xl;
        xl = xr;
        xr = temp;
    }

    private long F(long xl) {
        long a = (xl & 0xff000000) >> 24;
        long b = (xl & 0x00ff0000) >> 16;
        long c = (xl & 0x0000ff00) >> 8;
        long d = xl & 0x000000ff;

        long f = (si[0][(int) a] + si[1][(int) b]) % modulus;
        f = xor(f, si[2][(int) c]);
        f += si[3][(int) d];
        f %= modulus;
        return f;
    }

    byte[] encryptBlock64(byte[] data, byte[] bytesIV) throws UnsupportedEncodingException {

        byte[] bytesArrayForNextBlock = new byte[8];
        byte[] byteData = new byte[8];
        int length = data.length + 8;

        if (length % 8 != 0)
            while (length % 8 != 0)
                length++;

        byte[] tmpIntToByte;
        byte[] bytesOfInputArray = new byte[length];
        int[] tmpInt = new int[1];
        tmpInt[0] = data.length;
        tmpIntToByte = int2byte(tmpInt);
        System.arraycopy(tmpIntToByte,0,bytesOfInputArray,0,4);
        for (int i = 4; i < 8; i++)
            bytesOfInputArray[i] = 0;
        System.arraycopy(data, 0, bytesOfInputArray, 8, data.length);
        byte[] bytesOfOutputArray = new byte[length];

        System.arraycopy(bytesOfInputArray,0,byteData,0,8);
        byteData = setBlock(byteData,"encrypt");
        System.arraycopy(byteData,0,bytesOfOutputArray,0,8);

        System.arraycopy(bytesOfInputArray, 8, byteData, 0, 8);
        for (int i = 0; i < 8; i++)
            byteData[i] ^= bytesIV[i];
        byteData = setBlock(byteData, "encrypt");
        System.arraycopy(byteData, 0, bytesOfOutputArray, 8, 8);

        for (int i = 16; i < length; i += 8) {
            System.arraycopy(bytesOfInputArray, i, bytesArrayForNextBlock, 0, 8);
            for (int j = 0; j < 8; j++)
                byteData[j] ^= bytesArrayForNextBlock[j];
            byteData = setBlock(byteData, "encrypt");
            System.arraycopy(byteData, 0, bytesOfOutputArray, i, 8);
        }
        return bytesOfOutputArray;
    }

    private byte[] setBlock(byte[] block, String mode) throws UnsupportedEncodingException {

        byte[] tmp = new byte[8];

        if (mode.equals("encrypt")) {
            xl = unsignedLong(bytesToLong(block));
            xr = unsignedLong((bytesToLong(block)) >> 32);
            encipher();
        } else if (mode.equals("decrypt")) {
            xl = unsignedLong(bytesToLong(block));
            xr = unsignedLong((bytesToLong(block)) >> 32);
            decipher();
        }
        System.arraycopy(longToBytes(xl), 0, tmp, 0, 4);
        System.arraycopy(longToBytes(xr), 0, tmp, 4, 4);

        return tmp;
    }

    byte[] decryptBlock64(byte[] data, byte[] bytesIV) throws UnsupportedEncodingException {

        byte[] outputDataArray = new byte[data.length];
        byte[] arrayForNextBlock = new byte[8];
        byte[] arrayForNextPlusOneBlock = new byte[8];
        byte[] preLastBlock = new byte[8];
        byte[] byteData1 = new byte[8];
        byte[] myDecryptBytesArray = new byte[data.length];

        System.arraycopy(data, 0, myDecryptBytesArray, 0, data.length);
        System.arraycopy(myDecryptBytesArray, myDecryptBytesArray.length - 16, preLastBlock, 0, 8);

        System.arraycopy(myDecryptBytesArray,0,byteData1,0,8);
        byteData1 = setBlock(byteData1,"decrypt");
        System.arraycopy(byteData1,0,outputDataArray,0,8);

        System.arraycopy(myDecryptBytesArray, 8, byteData1, 0, 8);
        byteData1 = setBlock(byteData1, "decrypt");
        for (int j = 0; j < 8; j++)
            byteData1[j] ^= bytesIV[j];
        System.arraycopy(byteData1, 0, outputDataArray, 8, 8);

        for (int i = 8; i < data.length; i += 8) {
            if (i != data.length - 8) {
                System.arraycopy(myDecryptBytesArray, i, arrayForNextBlock, 0, 8);
                System.arraycopy(myDecryptBytesArray, i + 8, arrayForNextPlusOneBlock, 0, 8);
                arrayForNextPlusOneBlock = setBlock(arrayForNextPlusOneBlock, "decrypt");
                for (int j = 0; j < 8; j++)
                    arrayForNextPlusOneBlock[j] ^= arrayForNextBlock[j];
                System.arraycopy(arrayForNextPlusOneBlock, 0, outputDataArray, i + 8, 8);
            } else {
                System.arraycopy(myDecryptBytesArray, i, arrayForNextPlusOneBlock, 0, 8);
                arrayForNextPlusOneBlock = setBlock(arrayForNextPlusOneBlock, "decrypt");
                for (int j = 0; j < 8; j++)
                    arrayForNextPlusOneBlock[j] ^= preLastBlock[j];
                System.arraycopy(arrayForNextPlusOneBlock, 0, outputDataArray, i, 8);
            }
        }
        return outputDataArray;
    }

    private long xor(long a, long b) {
        return unsignedLong(a ^ b);
    }

    private long unsignedLong(long number) {
        return number & 0xffffffffL;
    }

    private long bytesToLong(byte[] key) {
        return (long) key[7] << 56 & 0xFF00000000000000L |
                (long) key[6] << 48 & 0x00FF000000000000L |
                (long) key[5] << 40 & 0x0000FF0000000000L |
                (long) key[4] << 32 & 0x000000FF00000000L |
                (long) key[3] << 24 & 0x00000000FF000000L |
                (long) key[2] << 16 & 0x0000000000FF0000L |
                (long) key[1] << 8 & 0x000000000000FFF0L |
                (long) key[0] & 0x00000000000000FFL;
    }

    private byte[] longToBytes(long value) {
        byte[] array = new byte[8];
        for (int i = 0; i < 8; i++)
            array[i] = (byte) ((value >> (i * 8)) & 0xFF);

        return array;
    }

    private byte[] int2byte(int[] src) {
        int srcLength = src.length;
        byte[] dst = new byte[srcLength << 2];

        for (int i = 0; i < srcLength; ++i) {
            int x = src[i];
            int j = i << 2;
            dst[j++] = (byte) (x >>> 24 & 255);
            dst[j++] = (byte) (x >>> 16 & 255);
            dst[j++] = (byte) (x >>> 8 & 255);
            dst[j++] = (byte) (x & 255);
        }
        return dst;
    }
}