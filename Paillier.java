import java.math.*;
import java.util.*;
import java.security.SecureRandom;

public class Paillier
{
    private final int CERTAINTY = 64;       // permet de générer des entiers premiers à partir d'un entier choisit aléatoirement : 1-2^(-CERTAINTY)
    private int bitLength;                  // longueur des cléfs
    private BigInteger p;                   // p entier aléatoire premier
    private BigInteger q;                   // q entier aléatoire premier (différent à p)
    private BigInteger phi;                 // phi =(p-1, q-1)
    private BigInteger n;                   // n = p*q
    private BigInteger ncarre;             // ncarre = n*n
    private BigInteger m;                  // le message claire
    
    public Paillier(int longueur) throws Exception {
    	
    	 m = new BigInteger("0");
        if ( longueur < 8) 
            throw new Exception("Paillier(int longueur): la longueur >= 8");
        
        bitLength = longueur;
        
        generateKeys();
    }
    
    public BigInteger getP() {
    	
        return p;
    }

    public BigInteger getQ(){
    	
        return q;
    }

    public BigInteger getphi(){
    	
        return phi;
    }

    public int getbitLength(){
    	
        return bitLength;
    }

    public BigInteger getN(){
    	
        return n;
    }

    public BigInteger getncarre(){
    	
        return ncarre;
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
        ncarre = n.multiply(n);        // ncarre = n*n
        
    }
    
    public BigInteger encrypt(BigInteger message) throws Exception {
    	
    	 m=message;
        // si m n'est pas dans (Z/Zn)
        if (m.compareTo(BigInteger.ZERO) < 0 || message.compareTo(n) >= 0)
        {
            throw new Exception("Paillier.encrypt(BigInteger m): le message claire m n'est pas dans (Z/nZ)");
        }
        
        // générer r, un entier aléatoire premier dans (Z/Zn)*
        BigInteger r = raleatoire();
        
 
        return (n.add(BigInteger.ONE)).modPow(m, ncarre).multiply(r.modPow(n, ncarre)).mod(ncarre);
    }

    public BigInteger decrypt(BigInteger c) throws Exception {
    	
        // si c n'est pas dans (Z/n^(2) Z)*
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(ncarre) >= 0 || c.gcd(ncarre).intValue() != 1)
        {
            throw new Exception("Paillier.decrypt(BigInteger c): le message claire c n'est pas dans (Z/n^(2) Z)*");
        }
        BigInteger x= phi.modInverse(n);
        
        return c.modPow(phi, ncarre).subtract(BigInteger.ONE).divide(n).multiply(x).mod(n);
    }
    
    public void printValues() {
    	
        System.out.println("p:       " + p);
        System.out.println("q:       " + q);
        System.out.println("phi:  " + phi);
        System.out.println("n:       " + n);
        System.out.println("n*n: " + ncarre);
    }
    

 // méthode qui retourne un entier aléatoire r dans (Z/nZ)*
    public BigInteger raleatoire() {
    	
        BigInteger r;
        
        do
        {
            r = new BigInteger(bitLength, new Random());
        }
        while (r.compareTo(n) >= 0 || r.gcd(n).intValue() != 1);
        
        return r;
    }
    

    
    public static void main(String str[])throws Exception {
    	
    	Scanner s =new Scanner(System.in);
    	Scanner z =new Scanner(System.in);
    	System.out.print("Donnez la taille des clefs: ");
    	int i =s.nextInt();
    	Paillier a = new Paillier(i);
    	a.printValues();
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
    	BigInteger u = (m.multiply(g)).mod(a.getncarre());
    	
    	///////// vérifier l'addition de deux messages chiffrées
    	BigInteger f = a.decrypt(u);
    	String j= f.toString();
    	System.out.println("Le message décrypté est : "+j);
    	
    }
}