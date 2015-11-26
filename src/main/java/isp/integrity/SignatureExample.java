package isp.integrity; /**
 * I0->I1->A1->B1->A2->B2->[A3]->B3
 * 
 * EXERCISE A3:
 * 
 * EXERCISE:
 * - Study this example.
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Signature
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */


import java.security.*;

public class SignatureExample {
    
    private static KeyPair kp;
    private static PublicKey pubSignKey;
    private static PrivateKey privSignKey;
    
    /**
     * Standard Algorithm Names
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    public static String KEYGEN_ALG = "RSA";
    public static String SIGN_ALG1 = "MD5withRSA";
    public static String SIGN_ALG2 = "SHA1withRSA";
    
    public static String TEXT = "We would like to provide data integrity.";
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        
        /**
         * STEP 1.
         * Alice creates public and private key. Bob receives her public key securely.
         */
        kp = KeyPairGenerator.getInstance(SignatureExample.KEYGEN_ALG).generateKeyPair();
        pubSignKey = kp.getPublic();
        privSignKey = kp.getPrivate();
        
        /**
         * Alice creates Signature object defining Signature algorithm.
         */
        Signature sig1 = Signature.getInstance(SignatureExample.SIGN_ALG1);
        
        /**
         * Alice initializes Signature object:
         * - Operation modes (SIGN) and
         * - provides appropriate ***Private*** Key
         */
        sig1.initSign(privSignKey);
        
        /**
         * Alice signs message
         */
        sig1.update(TEXT.getBytes());
        byte[] signed_TEXT = sig1.sign();
        
        /**
         * Bob creates Signature object defining Signature algorithm
         */
        Signature sig2 = Signature.getInstance(SignatureExample.SIGN_ALG1);
        
        /**
         * Bob initializes Signature object:
         * - Operation modes (VERIFY) and
         * - provides appropriate ***Public*** Key 
         */
        sig2.initVerify(pubSignKey);
        
        /**
         * Bob verifies received message providing
         * - received message and
         * - received signature.
         */
        sig2.update(TEXT.getBytes());
        if(true == sig2.verify(signed_TEXT))
            System.out.println("Signature is valid.");
        else
            System.out.println("Signature is *** NOT *** valid.");
    }
}
