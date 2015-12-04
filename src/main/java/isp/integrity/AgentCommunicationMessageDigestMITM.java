package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
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
 * channel, thus, HEX is used to transfer checksums.
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
public class AgentCommunicationMessageDigestMITM {

    private final static Logger LOG = Logger.getLogger(AgentCommunicationMessageDigestMITM.class.getCanonicalName());

    public static void main(String[] args) {

        /**
         * STEP 1.
         * Setup an insecure communication channel.
         */
        final BlockingQueue<String> alice2maloy = new LinkedBlockingQueue<>();
        final BlockingQueue<String> maloy2alice = new LinkedBlockingQueue<>();
        final BlockingQueue<String> maloy2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<String> bob2maloy = new LinkedBlockingQueue<>();

        /**
         * ALICE -> MALOY
         */
        final Agent alice = new Agent(alice2maloy,maloy2alice, null, null, null, "MD5") {

            @Override
            public void run() {
                try {
                    final String message = "I love you Bob. Kisses, Alice.";
                    outgoing.put(message);

                    final MessageDigest digestAlgorithm = MessageDigest.getInstance(this.macAlgorithm);
                    final byte[] hashed = digestAlgorithm.digest(message.getBytes("UTF-8"));


                    final String hashAsHex = DatatypeConverter.printHexBinary(hashed);
                    System.out.println(hashAsHex);


                    outgoing.put(hashAsHex);

                } catch (Exception e) {
                    LOG.severe("Exception: " + e.getMessage());
                }
            }
        };

        /**
         * MALOY
         */
        final MITMAgent maloy = new MITMAgent(maloy2alice,alice2maloy,maloy2bob,bob2maloy, null, null, null, "MD5") {

            @Override
            public void run() {
                try {

                    final String message = incomingA.take();
                    LOG.info("Evil Maloy : I have received: " + message);


                    final String receivedDigestString = incomingA.take();
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
         * BOB <- MALOY
         */
        final Agent bob = new Agent(bob2maloy,maloy2bob, null, null, null, "MD5") {

            @Override
            public void run() {
                try {

                    final String message = incoming.take();
                    LOG.info("Bob: I have received: " + message);


                    final String receivedDigestString = incoming.take();
                    final byte[] receivedDigest = DatatypeConverter.parseHexBinary(receivedDigestString);


                    final MessageDigest digestAlgorithm = MessageDigest.getInstance(this.macAlgorithm);
                    final byte[] digestRecomputed = digestAlgorithm.digest(message.getBytes("UTF-8"));


                    if (Arrays.equals(receivedDigest, digestRecomputed)) {
                        LOG.info("Integrity checked");
                    } else {
                        LOG.warning("Integrity check failed.");
                    }
                } catch (Exception e) {
                    LOG.severe("Exception: " + e.getMessage());
                }
            }
        };





        /**
         * STEP 4.
         * Two commands below "fire" both agents and the fun begins ... :-)
         */
        maloy.start();
        bob.start();
        alice.start();
    }
}
