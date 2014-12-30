# FPE for Java

## Format Preserving Encryption

* Cloned from DotFPE a NewBSD licensed implementation for .NET http://dotfpe.codeplex.com

* ... That in turn features one algorithm, which was ported from the Botan library http://botan.randombit.net/fpe.html.

* ... Using the scheme FE1 from the paper "Format-Preserving Encryption" by Bellare, Rogaway, et al. (http://eprint.iacr.org/2009/251)

So, the real credit is due to all authors in the chain!

## Usage
```java
import net._95point2.fpe.FPE

public static void main(String[] args) throws Exception 
{
    final int range = 10000;   // thus preserves the output range:  0 <= output < 10000
    final byte[] key = "Here is my secret key!".getBytes();
    final byte[] tweak = "tweak".getBytes();
    final BigInteger modulus = BigInteger.valueOf(range);

    

    BigInteger enc = encrypt(modulus, BigInteger.valueOf(i), key, tweak);
    BigInteger dec = decrypt(modulus, enc, key, tweak);
    
    System.out.println("
    
    if(enc.compareTo(dec) != 0){
        throw new IllegalStateException("Broken Implementation :( ");
    }
}
```
