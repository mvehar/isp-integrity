package isp.integrity; /**
 * I0->I1->A1->B1->A2->B2->A3->[B3]
 * 
 * EXERCISE B3:
 * An agent communication example. Message Authenticity and Integrity 
 * is provided using Digital Signature. Because private key is owned only
 * by one party, message source is verified and thus, 
 * non-repudiation property is provided.
 * 
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, Base64 encoding/decoding is used to transfer checksums.
 * 
 * A communication channel is implemented by thread-safe blocking queue using
 * linked-list data structure.
 * 
 * Both agent behavior are implemented by extending Agents class and
 * creating anonymous class and overriding run(...) method.
 * 
 * Both agents are "fired" at the end of the main method definition below.
 * 
 * EXERCISE:
 * - Study this example.
 * - Observe what happens if Alice's transmitter is corrupted?
 * - Observe both signatures in hexadecimal format (use Formatter).
 * 
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Signature
 * 
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */


import java.security.*;
import java.util.concurrent.*;

public class AgentCommunicationSignature {
    
    /**
     * Standard Algorithm Names
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    public static String KEYGEN_ALG = "RSA";
    public static String SIGN_ALG1 = "MD5withRSA";
    public static String SIGN_ALG2 = "SHA1withRSA";

    private static BlockingQueue<String> alice2bob;
    private static BlockingQueue<String> bob2alice;

    private static Agent alice;
    private static Agent bob;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        
        /**
         * STEP 1.
         * Alice creates public and private key. Bob receives her public key securly.
         */
        KeyPair keyPairAlice = KeyPairGenerator.getInstance(AgentCommunicationSignature.KEYGEN_ALG).generateKeyPair();
        PublicKey pubSignKeyAlice = keyPairAlice.getPublic();
        PrivateKey privSignKeyAlice = keyPairAlice.getPrivate();
        
        /**
         * STEP 2.
         * Setup a unsecure communication channel.
         */
        AgentCommunicationSignature.alice2bob = new LinkedBlockingQueue<String>();
        AgentCommunicationSignature.bob2alice = new LinkedBlockingQueue<String>();
        
        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o message
         *   o Signature
         * - uses private key to sign message.
         */
        alice = new Agent(bob2alice,alice2bob,null,null,privSignKeyAlice,SIGN_ALG1) {
            
            @Override
            public void run() {
                try {                  
                    /**
                     * STEP 3.1
                     * Alice writes a message and sends to Bob.
                     * This action is recorded in Alice's log.
                     */
                    String TEXT = "I love you Bob. Kisses, Alice.";
                    super.outgoing.put(TEXT);
                    System.out.println("[Alice::Log]: I have sent the following message to Bob.");
                    System.out.println("[Alice::Log]: message: " + TEXT);
                    
                    /**
                     * STEP 3.2
                     * In addition, Alice signs message using selected
                     * algorithm and her private key.
                     */
                    //TODO
                    //byte[] signed_TEXT
                    
                    /**
                     * STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //super.outgoing.put(Base64.encode(signed_TEXT));
                    
                } catch (Exception ex) {}
            }
        };
        
        /**
         * STEP 4.
         * Agent Bob definition:
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   o message
         *   o Signature
         * - uses Alice's public key to
         *   verify message authenticity and integrity. In addition,
         *   Alice cannot repudiate that she did not send the message.
         */
        bob = new Agent(alice2bob,bob2alice,null,null,pubSignKeyAlice,SIGN_ALG1){
            
            @Override
            public void run() {
                try {
                    /**
                     * STEP 4.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     * 
                     * IS AUTHENTICITIY AND INTEGRITIY PROPERTY PRESERVED? WE
                     * DO NOT KNOW THIS YET!!!
                     */
                    String received_TEXT = super.incoming.take();
                    System.out.println("[Bob::Log]: I have received the following message from Alice.");
                    System.out.println("[Bob::Log]: RECEIVED message: " + received_TEXT);
                    
                    /**
                     * STEP 4.2
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //byte[] received_signed_TEXT = Base64.decode(super.incoming.take()); /* */
                    
                    /**
                     * STEP 4.3
                     * Bob calculates setups signature verification. He has to provide
                     * received text and Alice's public key.
                     */
                    //TODO
                    //received_TEXT.getBytes()
                    
                    /**
                     * STEP 4.4
                     * Bob verifies Alice's signature.
                     */
                    //TODO
                    /*
                    if(true == sig.verify(received_signed_TEXT))
                        System.out.println("[Bob::Log]: message AUTHENTICITY AND INTEGRITY VERIFIED. NON-REPDUIATION IS PROVIDED.");
                    else
                        System.out.println("[Bob::Log]: message AUTHENTICITY AND INTEGRITY IS ***NOT*** VERIFIED.");
                    */
                               
                } catch (Exception ex) {}
            }
        };
        
        /**
         * STEP 5.
         * Two commands below "fire" both agents and the fun begins ... :-)
         */
        bob.start();
        alice.start();
    }
}
