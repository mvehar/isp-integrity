package isp.integrity; /**
 * I0->I1->A1->B1->A2->[B2]->A3->B3
 * <p/>
 * EXERCISE B2:
 * An agent communication example. Message Authenticity and Integrity
 * is provided using Hash algorithm and Shared Secret Key.
 * <p/>
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, string HEX encoding/decoding is used to transfer checksums.
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
import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * @author iztok
 */
public class AgentCommunicationHMAC {
    private final static Logger LOG = Logger.getLogger(AgentCommunicationHMAC.class.getCanonicalName());

    public static void main(String[] args) throws NoSuchAlgorithmException {

        /**
         * STEP 1.
         * Alice and Bob agree upon a shared secret session key that will be 
         * used for hash based message authentication code.
         */
        final Key hmacKey = KeyGenerator.getInstance("HmacMD5").generateKey();

        /**
         * STEP 2.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - uses shared secret session key to create HMAC.
         * - sends a message that is comprised of:
         *   o message
         *   o HMAC.
         */
        final Agent alice = new Agent(bob2alice, alice2bob, null, null, hmacKey, "HmacMD5") {
            @Override
            public void run() {
                try {
                    /**
                     * STEP 3.1
                     * Alice writes a message and sends to Bob.
                     */
                    final String text = "I love you Bob. Kisses, Alice.";
                    outgoing.put(text);

                    /**
                     * TODO: STEP 3.2
                     * In addition, Alice creates HMAC using selected
                     * hash algorithm and shared secret session key.
                     */
                    final Mac alg = Mac.getInstance(macAlgorithm);
                    alg.init(macKey);
                    final byte[] hmac = alg.doFinal(text.getBytes("UTF-8"));

                    /**
                     * TODO STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.printHexBinary(byte[])
                     */
                    final String hmacHEX = DatatypeConverter.printHexBinary(hmac);
                    outgoing.put(hmacHEX);
                    LOG.info("[Alice]: Sending '" + text + "' with hmac: '" + hmacHEX + "'");
                } catch (Exception ex) {
                    LOG.severe("Exception: " + ex.getMessage());
                }
            }
        };

        /**
         * STEP 4.
         * Agent Bob:
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   o message
         *   o HMAC
         * - uses shared secret session key to
         *   verify message authenticity and integrity.
         */
        final Agent bob = new Agent(alice2bob, bob2alice, null, null, hmacKey, "HmacMD5") {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 4.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     */
                    final String receivedText = incoming.take();
                    final String receivedHMACHex = incoming.take();
                    LOG.info("[Bob]: Received message '" + receivedText + "' with HMAC '" + receivedHMACHex + "'");

                    /**
                     * TODO: STEP 4.2
                     * Special care has to be taken when transferring binary stream
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.parseHexBinary(String)
                     */
                    final byte[] receivedHmac = DatatypeConverter.parseHexBinary(receivedHMACHex);

                    /**
                     * TODO: STEP 4.3
                     * Bob calculates new HMAC using selected hash algorithm,
                     * shared secret session key and received text.
                     */
                    final Mac alg = Mac.getInstance(macAlgorithm);
                    alg.init(macKey);
                    final byte[] recomputedHmac = alg.doFinal(receivedText.getBytes("UTF-8"));

                    /**
                     * TODO: STEP 4.4
                     * Verify if received and calculated HMAC match.
                     */
                    if (Arrays.equals(recomputedHmac, receivedHmac))
                        LOG.info("[Bob]: Authenticity and integrity verified.");
                    else
                        LOG.severe("[Bob]: Failed to verify authenticity and integrity.");

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
