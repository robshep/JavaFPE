# FPE for Java

## Format Preserving Encryption

* Cloned from DotFPE a NewBSD licensed implementation for .NET http://dotfpe.codeplex.com

* ... That in turn features one algorithm, which was ported from the Botan library http://botan.randombit.net/fpe.html.

* ... Using the scheme FE1 from the paper "Format-Preserving Encryption" by Bellare, Rogaway, et al. (http://eprint.iacr.org/2009/251)

So, the real credit is due to all authors in the chain!

## Usage
```java

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

import net._95point2.fpe.FPE;

public class FPETests
{
	@Test
	public void testBasic() throws Exception
	{
		final byte[] key = "Here is my secret key!".getBytes();
	    final byte[] tweak = "tweak".getBytes();
	    final int range = 1000;
		final BigInteger modulus = BigInteger.valueOf(range);
		
		BigInteger plain = BigInteger.valueOf(345);
		BigInteger enc = FPE.encrypt(modulus, plain, key, tweak);
		BigInteger dec = FPE.decrypt(modulus, enc, key, tweak);

		Assert.assertTrue( dec.compareTo(plain) == 0 );
	}
}
```
