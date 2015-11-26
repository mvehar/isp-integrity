package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
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
        final BlockingQueue<String> alice2bob = new LinkedBlockingQueue<String>();
        final BlockingQueue<String> bob2alice = new LinkedBlockingQueue<String>();

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
                    //LOG.info("Alice: Sending to Bob: " + message);

                    /**
                     * STEP 2.2
                     * In addition, Alice creates message digest using selected
                     * hash algorithm.
                     */
                    //TODO
                    //byte[] hash_TEXT

                    final MessageDigest digestAlgorithm = MessageDigest.getInstance("MD5");
                    final String hash = DatatypeConverter
                            .printHexBinary(digestAlgorithm.digest(message.getBytes("UTF-8")));

                    /**
                     * STEP 2.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //super.outgoing.put(Base64.encode(hash_TEXT));
                    outgoing.put(hash);
                    LOG.info("Alice: Sending to Bob: '" + message + "', hash: " + hash);
                } catch (Exception ex) {
                }
            }
        };

        /**
         * STEP 3.
         * Agent Bob definition:
         * - uses the communication channel,
         * - receives the message that is comprised of:
         *   o message
         *   o Message Digest
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
                     * STEP 3.2
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel, thus, 
                     * Base64 encoding/decoding is used to transfer checksums.
                     */
                    //TODO
                    //byte[] received_hash_TEXT = Base64.decode(super.incoming.take());

                    /**
                     * STEP 3.3
                     * Bob calculates new message digest using selected hash algorithm and
                     * received text.
                     */
                    //TODO
                    //byte[] calculated_hash_TEXT

                    /**
                     * STEP 3.4
                     * Verify if received and calculated message digest checksum match.
                     */
                    //TODO
                    /*
                    if(true == Arrays.equals(calculated_hash_TEXT, received_hash_TEXT))
                        System.out.println("[Bob::Log]: message INTEGRITY VERIFIED.");
                    else
                        System.out.println("[Bob::Log]: message INTEGRITY IS ***NOT*** VERIFIED.");
                    */

                } catch (Exception ex) {
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
