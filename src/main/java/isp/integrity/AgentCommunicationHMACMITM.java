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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * @author iztok
 */
public class AgentCommunicationHMACMITM {
    private final static Logger LOG = Logger.getLogger(AgentCommunicationHMACMITM.class.getCanonicalName());

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

        final BlockingQueue<String> alice2maloy = new LinkedBlockingQueue<>();
        final BlockingQueue<String> maloy2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<String> maloy2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2maloy = new LinkedBlockingQueue<>();


        /**
         * STEP 3.
         * Agent Alice definition:
         * - uses the communication channel,
         * - uses shared secret session key to create HMAC.
         * - sends a message that is comprised of:
         *   o message
         *   o HMAC.
         */
        final Agent alice = new Agent(maloy2alice, alice2maloy, null, null, hmacKey, "HmacMD5") {
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
                    final Mac hmacAlgorithm = Mac.getInstance("HmacMD5");
                    hmacAlgorithm.init(hmacKey);
                    final byte[] messageHmac = hmacAlgorithm.doFinal(text.getBytes("UTF-8"));


                    /**
                     * TODO STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.printHexBinary(byte[])

                     */
                    final String messageHmacAsString = DatatypeConverter.printHexBinary(messageHmac);
                    outgoing.put(messageHmacAsString);
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
        final Agent bob = new Agent(maloy2bob, bob2maloy, null, null, hmacKey, "HmacMD5") {

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
                    final Mac hmacAlgorithm = Mac.getInstance("HmacMD5");
                    hmacAlgorithm.init(hmacKey);
                    final byte[] recomputedHmac = hmacAlgorithm.doFinal(receivedText.getBytes("UTF-8"));
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
         * MALOY
         */
        final MITMAgent maloy = new MITMAgent(maloy2alice,alice2maloy,maloy2bob,bob2maloy, null, null, null, "HmacMD5") {

            @Override
            public void run() {
                try {

                    final String receivedText = incomingA.take();
                    final String receivedHMACHex = incomingA.take();
                    LOG.info("[Evil Maloy]: Received message '" + receivedText + "' with HMAC '" + receivedHMACHex + "'");

                    final Mac hmacAlgorithm = Mac.getInstance(this.macAlgorithm);

                    String possibleKey="";
                    for(char c='0';c<'z';c++){
                        hmacAlgorithm.init());

                    }


                    final byte[] receivedDigest = DatatypeConverter.parseHexBinary(receivedDigestString);


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance(this.macAlgorithm);
                    final byte[] digestRecomputed = digestAlgorithm.digest(message.getBytes("UTF-8"));


                    if (Arrays.equals(receivedDigest, digestRecomputed)) {
                        LOG.info("Integrity checked");
                    } else {
                        LOG.warning("Integrity check failed.");
                    }

                    //TODO: Modify message and send it to bob wit new MAC
                    LOG.info("Evil maloy will modify message..");
                    final String messageModified = "I hate you Bob. Alice.";
                    LOG.info("Sending modified msg: "+messageModified);
                    outgoingB.put(messageModified);

                    final byte[] hashedModified = digestAlgorithm.digest(messageModified.getBytes("UTF-8"));


                    final String hashAsHexModified = DatatypeConverter.printHexBinary(hashedModified);


                    outgoingB.put(hashAsHexModified);

                } catch (Exception e) {
                    LOG.severe("Exception: " + e.getMessage());
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
