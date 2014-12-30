/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2014,2015 Rob Shepherd
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package net._95point2.fpe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Software derived from a New-BSD licensed implementation for .NET http://dotfpe.codeplex.com
 *	... That in turn was ported from the Botan library http://botan.randombit.net/fpe.html.
 *	... Using the scheme FE1 from the paper "Format-Preserving Encryption" by Bellare, Rogaway, et al. (http://eprint.iacr.org/2009/251)
 *
 * @author Rob Shepherd
 *
 */
public class FPE 
{
    public static void main(String[] args) throws Exception 
    {
		final byte[] key = "Here is my secret key".getBytes();
		final byte[] tweak = "Here is my tweak".getBytes();
		
		
		final int range = 10000;
		final BigInteger modulus = BigInteger.valueOf(range);
		
		Set<BigInteger> results = new HashSet<BigInteger>();
		
		for(int i=0;i<range;i++){
			BigInteger enc = encrypt(modulus, BigInteger.valueOf(i), key, tweak);
			BigInteger dec = decrypt(modulus, enc, key, tweak);
			System.out.println(i + ": " + enc + " " + dec);
			if( dec.longValue() != i ){
				throw new IllegalStateException("enc (" + enc + ") != i(" + i + ")");
			}
			results.add(enc);
			if(results.size() != i+1){
				throw new IllegalStateException("duplicate enc: " + enc);
			}
			if(enc.longValue() < 0 || enc.longValue() > range){
				throw new IllegalStateException("enc " + enc + " out of range " + range);
			}
		}
	}
    // Normally FPE is for SSNs, CC#s, etc, nothing too big
    private static final int MAX_N_BYTES = 128 / 8;

    /// <summary>
    /// Generic Z_n FPE decryption, FD1 scheme
    /// </summary>
    /// <param name="modulus">Use to determine the range of the numbers. Example, if the
    /// numbers range from 0 to 999, use "1000" here.</param>
    /// <param name="ciphertext">The number to decrypt.</param>
    /// <param name="key">Secret key</param>
    /// <param name="tweak">Non-secret parameter, think of it as an IV - use the same one used to encrypt</param>
    /// <returns>The decrypted number</returns>
    public static BigInteger decrypt(BigInteger modulus, BigInteger ciphertext,byte[] key,byte[] tweak) throws Exception
    {
        FPE_Encryptor F = new FPE_Encryptor(key, modulus, tweak);

        BigInteger[] a_b = NumberTheory.factor(modulus);

        BigInteger a = a_b[0]; 
        BigInteger b = a_b[1];

        int r = rounds(a, b);

        BigInteger X = ciphertext;

        for (int i = 0; i != r; ++i)
        {
            BigInteger W = X.mod(a);
            BigInteger R = X.divide(a);

            BigInteger bigInteger = (W.subtract(F.F(r - i - 1, R)  ) );

            BigInteger L = bigInteger.mod(a);
            X = b.multiply(L).add(R);
        }

        return X;
    }

    /// <summary>
    /// Generic Z_n FPE encryption, FE1 scheme
    /// </summary>
    /// <param name="modulus">Use to determine the range of the numbers. Example, if the
    /// numbers range from 0 to 999, use "1000" here.</param>
    /// <param name="plaintext">The number to encrypt.</param>
    /// <param name="key">Secret key</param>
    /// <param name="tweak">Non-secret parameter, think of it as an IV</param>
    /// <returns>The encrypted number.</returns>
    public static BigInteger encrypt(BigInteger modulus, BigInteger plaintext,
                       byte[] key,
                       byte[] tweak) throws Exception
    {
        FPE_Encryptor F = new FPE_Encryptor(key, modulus, tweak);

        BigInteger[] a_b = NumberTheory.factor(modulus);

        BigInteger a = a_b[0]; 
        BigInteger b = a_b[1];
        int r = rounds(a, b);

        BigInteger X = plaintext;

        for (int i = 0; i != r; ++i)
        {
            BigInteger L = X.divide( b );
            BigInteger R = X.mod(b);

            BigInteger W = (L.add(F.F(i, R))).mod(a);
            X = a.multiply(R).add(W);
        }

        return X;
    }

    /// <summary>
    /// According to a paper by Rogaway, Bellare, etc, the min safe number
    /// of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) &lt;= 1
    /// so 3 rounds is safe. The FPE factorization routine should always
    /// return a >= b, so just confirm that and return 3.
    /// </summary>
    /// <param name="a"></param>
    /// <param name="b"></param>
    /// <returns></returns>
    private static int rounds(BigInteger a, BigInteger b) throws Exception
    {
        if (a.compareTo(b) < 0 )
            throw new Exception("FPE rounds: a < b");
        return 3;
    }

    /// <summary>
    /// A simple round function based on HMAC(SHA-256)
    /// </summary>
    private static class FPE_Encryptor
    {
        private Mac mac;

        private byte[] mac_n_t;

        public FPE_Encryptor(byte[] key, BigInteger n, byte[] tweak) throws Exception
        {
            mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
            mac.init(secret_key);

            byte[] n_bin = n.toByteArray();

            if (n_bin.length > MAX_N_BYTES)
                throw new Exception("N is too large for FPE encryption");

            ByteArrayOutputStream ms = new ByteArrayOutputStream();

            
            ms.write(n_bin.length);
            ms.write(n_bin);

            ms.write(tweak.length);
            ms.write(tweak);

            mac.reset();
            mac_n_t = mac.doFinal(ms.toByteArray());
        }

        public BigInteger F(int round_no, BigInteger R) throws IOException
        {
            byte[] r_bin = R.toByteArray();
            ByteArrayOutputStream ms = new ByteArrayOutputStream();
            ms.write(mac_n_t);
            ms.write(round_no);

            ms.write(r_bin.length);
            ms.write(r_bin);

            mac.reset();
            byte[] X = mac.doFinal(ms.toByteArray());
            
            byte[] X_ = new byte[X.length + 1];
            X_[0] = 0; // set the first byte to 0
            
            for(int i=0;i<X.length;i++){
            	X_[i+1] = X[i];
            }
            
            
            BigInteger ret = new BigInteger(X_);
            return ret;
        }
    }
    
    
    private static class NumberTheory
    {
    	private static final BigInteger MAX_PRIME = BigInteger.valueOf(65535);
    	/// <summary>
        /// Factor n into a and b which are as close together as possible.
        /// Assumes n is composed mostly of small factors which is the case for
        /// typical uses of FPE (typically, n is a power of 10)
        ///
        /// Want a >= b since the safe number of rounds is 2+log_a(b); if a >= b
        /// then this is always 3
        /// </summary>
        /// <param name="n"></param>
        /// <param name="a"></param>
        /// <param name="b"></param>
        public static BigInteger[] factor(BigInteger n) throws Exception
        {
        	BigInteger a = BigInteger.ONE;
        	BigInteger b = BigInteger.ONE;
            
            int n_low_zero = low_zero_bits(n);

            a = a.shiftLeft(n_low_zero / 2);
            b = b.shiftLeft(n_low_zero - (n_low_zero / 2) );
            
            n = n.shiftRight(n_low_zero);

            
            //for (int i = 0; i != PRIMES.length; ++i)
            BigInteger prime = BigInteger.ONE;
            while(prime.compareTo(MAX_PRIME) <= 0)
            {
            	prime = prime.nextProbablePrime();
                while (n.mod(prime).compareTo(BigInteger.ZERO) == 0)
                {
                    a = a.multiply( prime );
                    if ( a.compareTo(b) > 0) {
                    	BigInteger old_b = b;
                    	b = a;
                    	a = old_b;
                    }
                    n = n.divide( prime );
                }
                if(a.compareTo(BigInteger.ONE) > 0 && b.compareTo(BigInteger.ONE) > 0 )
                {
                	break;
                }
            }

            if (a.compareTo(b) > 0) {
            	BigInteger old_b = b;
            	b = a;
            	a = old_b;
            }
            a = a.multiply(n);
            if (a.compareTo(b) < 0) {
            	BigInteger old_b = b;
            	b = a;
            	a = old_b;
            }

            if (a.compareTo(BigInteger.ONE) < 0 || b.compareTo(BigInteger.ONE) < 0) {
                throw new Exception("Could not factor n for use in FPE");
            }
            
            // return 
            return new BigInteger[]{ a,b };
        }
        
    	/// <summary>
        /// Counts the trailing zeroes of a byte
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private static int ctz(byte n)
        {
            for (int i = 0; i != 8; ++i) {
                if (((n >> i) & 0x01) > 0) {
                    return i;
                }
    		}
            return 8;
        }
        
        /// <summary>
        /// Return the number of 0 bits at the end of n
        /// </summary>
        /// <param name="n"></param>
        /// <returns></returns>
        private static int low_zero_bits(BigInteger n)
        {
            int low_zero = 0;

            if (n.signum() > 0) {
                byte[] bytes = n.toByteArray();

                for (int i = bytes.length-1; i >=0 ; i--)
                {
                    int x =  (bytes[i] & 0xFF);

                    if (x > 0)
                    {
                        low_zero += ctz((byte)x);
                        break;
                    }
                    else
                        low_zero += 8;
                }
            }

            return low_zero;
        }
    }
}
