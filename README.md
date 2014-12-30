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

## Modulus

The modulus prescribes the range of numbers and is always powers of ten.
If the input range is 0 <= range <= 999
then then modulus must be set to 1000

### Example Output

```
Testing modulus: 0 -> 100
Plain: 35 Encrypted: 83
Plain: 35 Encrypted: 83
Plain: 7 Encrypted: 27
Plain: 53 Encrypted: 0
Plain: 32 Encrypted: 96

Testing modulus: 0 -> 1000
Plain: 520 Encrypted: 636
Plain: 754 Encrypted: 359
Plain: 580 Encrypted: 152
Plain: 855 Encrypted: 12
Plain: 926 Encrypted: 190

Testing modulus: 0 -> 10000
Plain: 2868 Encrypted: 10
Plain: 5210 Encrypted: 3455
Plain: 9410 Encrypted: 4502
Plain: 4864 Encrypted: 1730
Plain: 4974 Encrypted: 3599
```

## Further Notes

* When using a modulus of 100 and numbers in the range 0 <= range <= 99, there will usually be a collision where input==output.  


