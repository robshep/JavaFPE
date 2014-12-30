package net._95point2.fpe;

import java.math.BigInteger;
import java.util.Random;

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
	    final int range = 100;
		final BigInteger modulus = BigInteger.valueOf(range);
		
		BigInteger plain = BigInteger.valueOf(53);
		BigInteger enc = FPE.encrypt(modulus, plain, key, tweak);
		BigInteger dec = FPE.decrypt(modulus, enc, key, tweak);

		Assert.assertTrue( dec.compareTo(plain) == 0 );
	}
	
	@Test
	public void testRanges() throws Exception
	{
		final byte[] key = "Here is my secret key!".getBytes();
	    final byte[] tweak = "tweak".getBytes();
	    
		for(int pow=2;pow<5;pow++)
		{
			int power = (int) Math.pow(10, pow);
			
			final int range = power;   // thus preserves the output range:  0 <= output < range
			final BigInteger modulus = BigInteger.valueOf(range);
			
			System.out.print("Testing 0 -> " + power);
			int count = 0;
			for(int i=0;i<power;i++){
				
				BigInteger plain = BigInteger.valueOf(i);
			    BigInteger enc = FPE.encrypt(modulus, plain, key, tweak);
			    BigInteger dec = FPE.decrypt(modulus, enc, key, tweak);

			    Assert.assertTrue( plain.compareTo(dec) == 0 );
			    
			    Assert.assertTrue(enc.compareTo(BigInteger.ZERO) >= 0);
			    Assert.assertTrue( enc.compareTo(modulus) < 0);
			    count++;
			}
			System.out.println(" OK (" + count + ")");
			
		}
	}
	
	@Test
	public void testKey() throws Exception
	{
		final byte[] key1 = "I've got the key, I've got the secret".getBytes();
		final byte[] key2 = "I've got the key to a ... another way-eee-aaay".getBytes();
	    final byte[] tweak = "tweak".getBytes();
	    
	    final int range = 10000;
	    final BigInteger modulus = BigInteger.valueOf(range);
	    
	    Random rand = new Random();
	    
		for(int i=0;i<10000; i++)
		{
			BigInteger plain = BigInteger.valueOf(rand.nextInt(range));
		    BigInteger enc1 = FPE.encrypt(modulus, plain, key1, tweak);
		    BigInteger enc2 = FPE.encrypt(modulus, plain, key2, tweak);
		    BigInteger dec1 = FPE.decrypt(modulus, enc1, key1, tweak);
		    BigInteger dec2 = FPE.decrypt(modulus, enc1, key1, tweak);

		    Assert.assertTrue( plain.compareTo(dec1) == 0 );
		    Assert.assertTrue( dec1.compareTo(dec2) == 0 );
		    Assert.assertTrue( enc1.compareTo(enc2) != 0 );
		}
	}
	
	@Test
	public void testWrongKey() throws Exception
	{
		final byte[] key1 = "I've got the key, I've got the secret".getBytes();
		final byte[] key2 = "I've got the key to a ... another way-eee-aaay".getBytes();
	    final byte[] tweak = "tweak".getBytes();
	    
	    final int range = 10000;
	    final BigInteger modulus = BigInteger.valueOf(range);
	    
	    Random rand = new Random();
	    
		for(int i=0;i<10000; i++)
		{
			BigInteger plain = BigInteger.valueOf(rand.nextInt(range));
		    BigInteger enc1 = FPE.encrypt(modulus, plain, key1, tweak);
		    BigInteger dec2 = FPE.decrypt(modulus, enc1, key2, tweak);

		    Assert.assertTrue( plain.compareTo(dec2) != 0 );
		}
	}
	
	@Test
	public void testTweak() throws Exception
	{
		final byte[] key = "I've got the key, I've got the secret".getBytes();
		final byte[] tweak1 = "tweak no.1".getBytes();
	    final byte[] tweak2 = "tweak, tweak, tweeeek".getBytes();
	    
	    final int range = 10000;
	    final BigInteger modulus = BigInteger.valueOf(range);
	    
	    Random rand = new Random();
	    
		for(int i=0;i<10000; i++)
		{
			BigInteger plain = BigInteger.valueOf(rand.nextInt(range));
		    BigInteger enc1 = FPE.encrypt(modulus, plain, key, tweak1);
		    BigInteger enc2 = FPE.encrypt(modulus, plain, key, tweak2);
		    BigInteger dec1 = FPE.decrypt(modulus, enc1, key, tweak1);
		    BigInteger dec2 = FPE.decrypt(modulus, enc2, key, tweak2);

		    Assert.assertTrue( plain.compareTo(dec1) == 0 );
		    Assert.assertTrue( dec1.compareTo(dec2) == 0 );
		    Assert.assertTrue( enc1.compareTo(enc2) != 0 );
		}
	}
}
