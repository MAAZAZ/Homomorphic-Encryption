import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;
    

public class RSA {
	private final int CERTAINTY = 64;       // permet de g�n�rer des entiers premiers � partir d'un entier choisit al�atoirement : 1-2^(-CERTAINTY)
    private int bitLength;                  // longueur des cl�fs
    private BigInteger p;                   // p entier al�atoire premier
    private BigInteger q;                   // q entier al�atoire premier (diff�rent � p)
    private BigInteger phi;                 // phi =(p-1, q-1)
    private BigInteger n;                   // n = p*q
    private BigInteger m;                  // le message claire
    private BigInteger d;                  // la cl� public
    private BigInteger e;                  // la cl� priv�e

   
   RSA(int longueur) throws Exception {
	   
	   m = new BigInteger("0");
	   
       if ( longueur < 8) 
           throw new Exception("Paillier(int longueur): la longueur >= 8");
       
       bitLength = longueur;
       
       generateKeys();
       
       
       }
      
   public BigInteger getn() {
	   return n;
   }
   
   public void generateKeys(){
   	
       p = new BigInteger(bitLength / 2, CERTAINTY, new Random());     // p entier al�atoire
       
       do
       {
           q = new BigInteger(bitLength / 2, CERTAINTY, new Random()); // q entier al�atoire (diff�rent � p)
       }
       while (q.compareTo(p) == 0);

       phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
       
       n = p.multiply(q);              // n = p*q
       d = daleatoire();
       e = d.modInverse(phi);
   }
   
  // m�thode qui retourne un entier al�atoire d  dans (Z/nZ)*
   public BigInteger daleatoire() {
   	
       BigInteger d;
       
       do
       {
           d = new BigInteger(bitLength, new Random());
       }
       while (d.compareTo(phi) >= 0 || d.gcd(phi).intValue() != 1);
       
       return d;
   }
   

   BigInteger encrypt(BigInteger m) {
      return m.modPow(d, n);
   }

   BigInteger decrypt(BigInteger encrypted) {
      return encrypted.modPow(e,n);
   }

   public String toString() {
      String s = "";
      s +="p = " + p + "\n";
      s +="q = " + q + "\n";
      s += "Modulo = " + n + "\n";
      s += "La cl� public  = " + d  + "\n";
      s += "La cl� priv�e = " + e + "\n";
      return s;
   }
 
   
   public static void main(String str[])throws Exception {
   	
   	Scanner s =new Scanner(System.in);
   	Scanner z =new Scanner(System.in);
   	System.out.print("Donnez la taille des clefs: ");
   	int i =s.nextInt();
   	RSA a = new RSA(i);
   	System.out.print(a.toString());
   	System.out.print("Donnez le message : ");
   	BigInteger e = s.nextBigInteger();
   	System.out.print("Donnez un autre message : ");
   	BigInteger n = z.nextBigInteger();
   	//String o= e.toString();
   	//System.out.print(o);
   	BigInteger g =  a.encrypt(e);
   	String o= g.toString();
   	
   	BigInteger m =  a.encrypt(n);
   	String w = m.toString();
   	
   	System.out.println("Le 1er message crypt�e est  : "+o);
   	System.out.println("la 2eme message crypt�e est : "+w);
   	
    //////produit g et m: 
  	BigInteger u = (m.multiply(g)).mod(a.getn());
  	
   	
   	///////// v�rifier la multiplication de deux messages chiffr�es
   	BigInteger f = a.decrypt(u);
   	String j= f.toString();
   	System.out.println("Le message d�crypt� est : "+j);
   	
   }
}