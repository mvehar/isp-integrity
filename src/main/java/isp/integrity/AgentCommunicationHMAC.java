package isp.integrity; /**
 * I0->I1->A1->B1->A2->[B2]->A3->B3
 * <p/>
 * EXERCISE B2:
 * An agent communication example. Message Authenticity and Integrity
 * is provided using Hash algorithm and Shared Secret Key.
 * <p/>
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, Base64 encoding/decoding is used to transfer checksums.
 * <p/>
 * A communication channel is implemented by thread-safe blocking queue using
 * linked-list data structure.
 * <p/>
 * Both agent behavior are implemented by extending Agents class and
 * creating anonymous class and overriding run(...) method.
 * <p/>
 * Both agents are "fired" at the end of the main method definition below.
 * <p/>
 * EXERCISE:
 * - Study this example.
 * - Observe what happens if Bob's receiver is corrupted?
 * - Observe both HMACs in hexadecimal format (use Formatter).
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Mac
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 12. 12. 2011
 * @version 1
 */

import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * @author iztok
 */
public class AgentCommunicationHMAC {

    /**
     * Standard Algorithm Names
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    public static final String HMAC_ALG1 = "HmacMD5";
    public static final String HMAC_ALG2 = "HmacSHA1";

    public static void main(String[] args) throws NoSuchAlgorithmException {

        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be 
         * used for hash based message authentication code.
         */
        final Key hmacKey = KeyGenerator.getInstance(HMACExample.HMAC_ALG1).generateKey();

        /**
         * STEP 2.
         * Setup a (un)secure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<String>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<String>();

        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o message
         *   o HMAC
         * - uses shared secret session key to
         *   create HMAC.
         */
        final Agent alice = new Agent(bob2alice, alice2bob, null, null, hmacKey, null) {

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
                     * In addition, Alice creates HMAC using selected
                     * hash algorithm and shared secret session key.
                     */
                    //TODO
                    //byte[] hmac_TEXT

                    /**
                     * STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //super.outgoing.put(Base64.encode(hmac_TEXT));

                } catch (Exception ex) {
                }
            }
        };

        /**
         * STEP 4.
         * Agent Bob definition:
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   o message
         *   o HMAC
         * - uses shared secret session key to
         *   verify message authenticity and integrity.
         */
        final Agent bob = new Agent(alice2bob, bob2alice, null, null, hmacKey, null) {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 4.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     *
                     * IS AUTHENTICITY AND INTEGRITY PROPERTY PRESERVED??? WE
                     * DO NOT KNOW THIS YET!!!
                     */
                    String received_TEXT = incoming.take();
                    System.out.println("[Bob::Log]: I have received the following message from Alice.");
                    System.out.println("[Bob::Log]: RECEIVED message: " + received_TEXT);

                    /**
                     * STEP 4.2
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //byte[] received_hmac_TEXT = Base64.decode(super.incoming.take());

                    /**
                     * STEP 4.3
                     * Bob calculates new HMAC using selected hash algorithm,
                     * shared secret session key and received text.
                     */
                    //TODO
                    //byte[] calculated_hmac_TEXT

                    /**
                     * STEP 4.4
                     * Verify if received and calculated HMAC match.
                     */
                    //TODO
                    /*
                    if(true == Arrays.equals(calculated_hmac_TEXT, received_hmac_TEXT))
                        System.out.println("[Bob::Log]: message AUTHENTICITY AND INTEGRITY VERIFIED.");
                    else
                        System.out.println("[Bob::Log]: message AUTHENTICITY AND INTEGRITY IS ***NOT*** VERIFIED.");
                    */

                } catch (Exception ex) {
                }
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
