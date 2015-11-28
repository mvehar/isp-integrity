package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

/**
 * I0->I1->A1->B1->A2->B2->A3->[B3]
 * <p/>
 * EXERCISE B3:
 * An agent communication example. The authenticity and integrity of messages
 * are provided with the use of digital signatures.
 * <p/>
 * Additionally, since the signing key (private key) is owned only by the signee,
 * we can be certain that valid signature can only be provided by that party. This
 * provides an additional property called non-repudiation.
 * <p/>
 * Special care has to be taken when transferring binary stream over the communication
 * channel, thus, HEX encoding as strings is used to transfer checksums.
 * <p/>
 * A communication channel is implemented by thread-safe blocking queue.
 * <p/>
 * Both agent behavior are implemented by extending Agents class and
 * creating anonymous class and overriding run(...) method.
 * <p/>
 * Both agents are started at the end of the main method definition below.
 * <p/>
 * EXERCISE:
 * - Study the example.
 * - Observe both signatures in hexadecimal format
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#Signature
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 12. 12. 2011
 */
public class AgentCommunicationSignature {
    private final static Logger LOG = Logger.getLogger(AgentCommunicationHMAC.class.getCanonicalName());

    public static void main(String[] args) throws NoSuchAlgorithmException {

        /**
         * STEP 1.
         * Alice creates public and private key. Bob receives her public key.
         */
        final KeyPair keyPairAlice = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final PublicKey pkAlice = keyPairAlice.getPublic();
        final PrivateKey skAlice = keyPairAlice.getPrivate();

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
         * - sends a message that is comprised of:
         *   o message
         *   o Signature
         * - uses private key to sign message.
         */
        final Agent alice = new Agent(bob2alice, alice2bob, null, null, skAlice, "SHA1withRSA") {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 3.1
                     * Alice writes a message and sends to Bob.
                     * This action is recorded in Alice's log.
                     */
                    final String text = "I love you Bob. Kisses, Alice.";
                    outgoing.put(text);

                    /**
                     * TODO STEP 3.2
                     * In addition, Alice signs message using selected
                     * algorithm and her private key.
                     */

                    final Signature alg = Signature.getInstance(macAlgorithm);
                    alg.initSign(skAlice);
                    alg.update(text.getBytes("UTF-8"));
                    final byte[] signature = alg.sign();

                    /**
                     * TODO: STEP 3.3
                     * Special care has to be taken when transferring binary stream 
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.printHexBinary(byte[])
                     */
                    final String signatureHex = DatatypeConverter.printHexBinary(signature);
                    outgoing.put(signatureHex);
                    LOG.info("[Alice]: Sending: " + text + " with signature: " + signatureHex);
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
         *   o Signature
         * - uses Alice's public key to
         *   verify message authenticity and integrity. In addition,
         *   Alice cannot repudiate that she did not send the message.
         */
        final Agent bob = new Agent(alice2bob, bob2alice, null, null, pkAlice, "SHA1withRSA") {

            @Override
            public void run() {
                try {
                    /**
                     * STEP 4.1
                     * Bob receives the message from Alice.
                     * This action is recorded in Bob's log.
                     */
                    final String receivedText = incoming.take();
                    final String receivedSignatureHex = incoming.take();
                    LOG.info("[Bob] Received: " + receivedText + " with signature: " + receivedSignatureHex);

                    /**
                     * TODO STEP 4.2
                     * Special care has to be taken when transferring binary stream
                     * over the communication channel: convert byte array into string
                     * of HEX values with DatatypeConverter.parseHexBinary(String)
                     */
                    final byte[] receivedSignature = DatatypeConverter.parseHexBinary(receivedSignatureHex);

                    /**
                     * STEP 4.3
                     * Bob setups signature verification. He has to provide
                     * received text and Alice's public key.
                     */
                    final Signature alg = Signature.getInstance(macAlgorithm);
                    alg.initVerify(pkAlice);
                    alg.update(receivedText.getBytes("UTF-8"));

                    /**
                     * TODO: STEP 4.4
                     * Bob verifies Alice's signature.
                     */
                    if (alg.verify(receivedSignature))
                        LOG.info("[Bob]: Signature OK");
                    else
                        LOG.severe("[Bob]: Invalid signature");

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
