import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;
    

public class RSA {
	private final int CERTAINTY = 64;       // permet de générer des entiers premiers à partir d'un entier choisit aléatoirement : 1-2^(-CERTAINTY)
    private int bitLength;                  // longueur des cléfs
    private BigInteger p;                   // p entier aléatoire premier
    private BigInteger q;                   // q entier aléatoire premier (différent à p)
    private BigInteger phi;                 // phi =(p-1, q-1)
    private BigInteger n;                   // n = p*q
    private BigInteger m;                  // le message claire
    private BigInteger d;                  // la clé public
    private BigInteger e;                  // la clé privée

   
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
   	
       p = new BigInteger(bitLength / 2, CERTAINTY, new Random());     // p entier aléatoire
       
       do
       {
           q = new BigInteger(bitLength / 2, CERTAINTY, new Random()); // q entier aléatoire (différent à p)
       }
       while (q.compareTo(p) == 0);

       phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
       
       n = p.multiply(q);              // n = p*q
       d = daleatoire();
       e = d.modInverse(phi);
   }
   
  // méthode qui retourne un entier aléatoire d  dans (Z/nZ)*
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
      s += "La clé public  = " + d  + "\n";
      s += "La clé privée = " + e + "\n";
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
   	
   	System.out.println("Le 1er message cryptée est  : "+o);
   	System.out.println("la 2eme message cryptée est : "+w);
   	
    //////produit g et m: 
  	BigInteger u = (m.multiply(g)).mod(a.getn());
  	
   	
   	///////// vérifier la multiplication de deux messages chiffrées
   	BigInteger f = a.decrypt(u);
   	String j= f.toString();
   	System.out.println("Le message décrypté est : "+j);
   	
   }
}