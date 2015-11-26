package isp.integrity; /**
 * I0->I1->A1->B1->A2->B2->A3->B3->A4->B4->A5->[I2]
 * 
 * EXERCISE I2:
 * In exercise we have used "AES/CBC/PKCS5Padding" symmetric cipher algorithm
 * to provide confidentiality. CBC operation mode uses IV (Init. Vector), that
 * has to be a random number and cipher object initialization infrastructure
 * provides this value transparently and automatically.
 * 
 * Lets observe how secure random numbers are created manually.
 * 
 * EXERCISE:
 * - Study this example.
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#SecureRandom
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 19. 12. 2011
 * @version 1
 */


import java.security.*;
import java.util.Formatter;

public class SecureRandomExample {

    /**
     * RANDOM NUMBER LENGTH
     */
    private static int RND_LENGTH = 128;
   
    public static void main(String[] args) throws NoSuchAlgorithmException{
        
        /**
         * STEP 1.
         * Create Secure Random Number Generator (RNG). It differs from Random class
         * in that it produces cryptographically strong random numbers.
         * 
         * Call getInstance(...) factory static method to create sc1 object!
         */
        SecureRandom sc1 = SecureRandom.getInstance("SHA1PRNG");
        
        /**
         * STEP 2.
         * To get random bytes, a caller simply passes an array of any length, which is
         * filled with random bytes.
         */
        byte[] rnd =new byte[SecureRandomExample.RND_LENGTH];
        sc1.nextBytes(rnd);
        
        /**
         * STEP 3.
         * Use random numbers to create Secret Key or simply to print out like shown
         * in an example below.
         */
        Formatter frm1 = new Formatter();
        for (byte b : rnd)
            frm1.format("%02x", b);
        System.out.println(frm1.toString());
    }
}
