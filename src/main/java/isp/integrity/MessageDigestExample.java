package isp.integrity;

import javax.xml.bind.DatatypeConverter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * I0->I1->[A1]->B1->A2->B2->A3->B3
 * <p/>
 * EXERCISE A1:Study
 * <p/>
 * INFO:
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#MessageDigest
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 12. 12. 2011
 */
public class MessageDigestExample {

    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        final String message = "We would like to provide data integrity.";

        /**
         * STEP 1.
         * Select Message Digest algorithm and get new Message Digest object instance
         * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
         */
        final MessageDigest digestAlgorithm = MessageDigest.getInstance("MD5");

        /**
         * STEP 2.
         * Create new hash using message digest object.
         */
        final byte[] hashed = digestAlgorithm.digest(message.getBytes("UTF-8"));

        /**
         * STEP 4: Print out hash. Note we have to convert a byte array into
         * hexadecimal string representation.
         */
        System.out.println(DatatypeConverter.printHexBinary(hashed));
    }
}
