package isp.integrity; /**
 * [I0]->I1->A1->B1->A2->B2->A3->B3
 * <p/>
 * EXERCISE I0: Make sure you understand this example.
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @date 26. 11. 2015
 * @version 1
 */

import java.security.Key;
import java.util.concurrent.BlockingQueue;

/**
 * Represents an agent that can communicate with other agents using
 * ideal communication channel.
 * <p/>
 * Agent's behavior is implemented by extending Agents class and
 * overriding run(...) method.
 */
public abstract class MITMAgent extends Thread {
    protected final BlockingQueue<String> outgoingA, incomingA;
    protected final BlockingQueue<String> outgoingB, incomingB;

    protected final Key macKey, cryptoKey;
    protected final String cryptoAlgorithm, macAlgorithm;

    public MITMAgent(final BlockingQueue<String> outgoingA, final BlockingQueue<String> incomingA,final BlockingQueue<String> outgoingB, final BlockingQueue<String> incomingB, final Key cryptoKey,
                     final String cryptoAlgorithm, final Key macKey, final String macAlgorithm) {
        this.outgoingA = outgoingA;
        this.incomingA = incomingA;
        this.outgoingB = outgoingB;
        this.incomingB = incomingB;

        this.cryptoKey = cryptoKey;
        this.cryptoAlgorithm = cryptoAlgorithm;
        this.macKey = macKey;
        this.macAlgorithm = macAlgorithm;
    }


}
