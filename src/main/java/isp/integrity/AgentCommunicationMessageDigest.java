package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * I0->I1->A1->[B1]->A2->B2->A3->B3
 * <p/>
 * EXERCISE B1: Providing integrity to agent communications
 * <p/>
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, Base64 encoding/decoding is used to transfer checksums.
 * <p/>
 * A communication channel is implemented by thread-safe blocking queue using
 * linked-list data structure.
 * <p/>
 * Both agents are implemented with class Agent.
 * <p/>
 * Both agents are started at the end of the main method definition below.
 * <p/>
 * EXERCISE:
 * - Study example.
 * - Observe what happens if Alice's transmitter is corrupted?
 * - Observe both checksums in hexadecimal format (use Formatter).
 * - Mount a Man-in-The-Middle attack (after B3 is completed).
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#MessageDigest
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 12. 12. 2011
 */
public class AgentCommunicationMessageDigest {

    private final static Logger LOG = Logger.getLogger(AgentCommunicationMessageDigest.class.getCanonicalName());

    public static void main(String[] args) {

        /**
         * STEP 1.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<>();

        /**
         * STEP 2.
         * Agent Alice definition:
         * - uses the communication channel,
         * - sends a message that is comprised of:
         *   o message
         *   o Message Digest
         * - checks if received and calculated message digest checksum match.
         */
        final Agent alice = new Agent(bob2alice, alice2bob, null, null, null, "MD5") {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 2.1
                     * Alice writes a message and sends to Bob.
                     * This action is recorded in Alice's log.
                     *
                     * IS INTEGRITY PROPERTY PRESERVED??? WE DO NOT KNOW THIS YET!!!
                     */
                    final String message = "I love you Bob. Kisses, Alice.";
                    outgoing.put(message);

                    /**
                     * TODO: STEP 2.2
                     * In addition, Alice creates message digest using selected
                     * hash algorithm.
                     */
                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("MD5");
                    final byte[] digest = digestAlgorithm.digest(message.getBytes("UTF-8"));
                    final String digestAsHex = DatatypeConverter.printHexBinary(digest);

                    /**
                     * TODO STEP 2.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.printHexBinary(byte[])
                     */
                    outgoing.put(digestAsHex);
                    LOG.info("Alice: Sending to Bob: '" + message + "', digest: " + digestAsHex);
                } catch (InterruptedException | NoSuchAlgorithmException | UnsupportedEncodingException e) {
                    LOG.severe("Exception: " + e.getMessage());
                }
            }
        };

        /**
         * STEP 3. Agent Bob
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   - message
         *   - message digest
         * - checks if received and calculated message digest checksum match.
         */
        final Agent bob = new Agent(alice2bob, bob2alice, null, null, null, "MD5") {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 3.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     */
                    final String message = incoming.take();
                    LOG.info("Bob: I have received: " + message);

                    /**
                     * TODO STEP 3.2
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel: convert received string into
                     * byte array with DatatypeConverter.parseHexBinary(String)
                     */
                    final String receivedDigestAsHex = incoming.take();
                    final byte[] receivedDigest = DatatypeConverter.parseHexBinary(receivedDigestAsHex);

                    /**
                     * TODO: STEP 3.3
                     * Bob calculates new message digest using selected hash algorithm and
                     * received text.
                     */
                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("MD5");
                    final byte[] computedDigest = digestAlgorithm.digest(message.getBytes("UTF-8"));

                    /**
                     * TODO STEP 3.4
                     * Verify if received and calculated message digest checksum match.
                     */
                    if (Arrays.equals(receivedDigest, computedDigest)) {
                        LOG.info("Integrity checked");
                    } else {
                        LOG.warning("Integrity check failed.");
                    }
                } catch (InterruptedException | NoSuchAlgorithmException | UnsupportedEncodingException e) {
                    LOG.severe("Exception: " + e.getMessage());
                }
            }
        };

        /**
         * STEP 4.
         * Two commands below "fire" both agents and the fun begins ... :-)
         */
        bob.start();
        alice.start();
    }
}
