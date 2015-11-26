package isp.integrity; /**
 * I0->I1->A1->B1->[A2]->B2->A3->B3
 * 
 * EXERCISE A2:
 * 
 * EXERCISE:
 * - Study this example.
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */


import java.security.*;
import javax.crypto.*;
import java.util.Formatter;

public class HMACExample {

    /**
     * Standard Algorithm Names
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    public static String HMAC_ALG1 = "HmacMD5";
    public static String HMAC_ALG2 = "HmacSHA1";
    
    public static String TEXT = "We would like to provide data integrity.";
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
        
        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be 
         * used for hash based message authentication code.
         */
        final Key hmacKey = KeyGenerator.getInstance(HMACExample.HMAC_ALG1).generateKey();
        
        /**
         * STEP 2.
         * Select HMAC algorithm and get new HMAC object instance.
         */
        final Mac hmac = Mac.getInstance(HMACExample.HMAC_ALG1);
        
        /**
         * STEP 3.
         * Initialize HMAC and provide shared secret session key. Create HMAC message.
         */
        hmac.init(hmacKey);
        byte[] hmac_TEXT = hmac.doFinal(HMACExample.TEXT.getBytes());
        
        /**
         * STEP 4.
         * Print out HMAC.
         */
        Formatter frm1 = new Formatter();
        for (byte b : hmac_TEXT)
            frm1.format("%02x", b);
        System.out.println("HMAC Key Hex Representation:" + frm1.toString());
    }
    
}
