

import java.math.BigInteger;
import java.security.SecureRandom;

public class GoldwasserMicali {

	/**
	 * SYSTEM PARAMETERS
	 */
	//Bitsize
	private int bitSize;
	
	/**
	 * KEYS
	 */
	//Private key
	private BigInteger p,q;
	//Public key
	private BigInteger x,n;
	
	//Random number generator
	public SecureRandom rand;
	
	/**
	 * Constructor generating key parameters
	 * @param bitSize: size in bits of p and q, this number must be a power of 2, for 1024 security bitSize must be 512.
	 */
	public GoldwasserMicali(int bitSize){
		this.bitSize=bitSize;
		this.rand=new SecureRandom();
		generateKeys();
	}
	/**
	 * Key parameters of Benaloh's cryptosystem 
	 */
	public void generateKeys(){
		BigInteger one=BigInteger.ONE,two=new BigInteger("2");
		p=randomNumber(true,bitSize);
		do{
			q=randomNumber(true,bitSize);
		}while(p.equals(q));
		n=p.multiply(q);
		do{
			x=randomNumber(false,bitSize*2);
		}while(x.compareTo(n)>=0 || x.modPow(p.subtract(one).divide(two), p).equals(one) || x.modPow(q.subtract(one).divide(two), q).equals(one));
	}

	/**
	 * BigInteger random number generator
	 * @param prime true if the number must be prime, false otherwise
	 * @param size: size in bits
	 * @return random number with the criteria selected.
	 */
	private BigInteger randomNumber(boolean prime, int size){
		if(prime)
			return BigInteger.probablePrime(size, rand);
		BigInteger number=null;
		byte bNumber[]=new byte[(int)Math.ceil(size/8.0)];
		do{
			rand.nextBytes(bNumber);
			number=new BigInteger(bNumber);
		}while(number.compareTo(BigInteger.ZERO)<=0);
		return number;
	}
	
	public BigInteger encrypt(boolean bit){
		BigInteger y;
		do{
			y=randomNumber(false, bitSize*2);
		}while(y.compareTo(n)>=0);
		return y.modPow(new BigInteger("2"), n).multiply(bit?x:BigInteger.ONE).remainder(n);
	}
	
	public boolean decrypt(BigInteger c){
		boolean qr;
		qr=c.modPow(p.subtract(BigInteger.ONE).divide(new BigInteger("2")), p).equals(BigInteger.ONE);
		qr&=c.modPow(q.subtract(BigInteger.ONE).divide(new BigInteger("2")), q).equals(BigInteger.ONE);
		return qr;
	}
	
	public static void main(String[] args) {
		String m="110";
		GoldwasserMicali gm=new GoldwasserMicali(512);
		System.out.println(m);
		for(int i=0;i<m.length();i++){
			BigInteger c=gm.encrypt(m.charAt(i)=='1');
			System.out.print((gm.decrypt(c)?0:1));
		}
	}
}