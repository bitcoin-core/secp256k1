package org.bitcoin;

import com.google.common.io.BaseEncoding;
import java.util.Arrays;
import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;
import static org.bitcoin.NativeSecp256k1Util.*;

/**
 * This class holds test cases defined for testing this library.
 */
public class NativeSecp256k1RecoveryTest {
    /**
      * This tests signRecoverable() for a valid secretkey. Unlike sign, which uses DER format,
      * signRecoverable uses compact format for the signature.
      */
    public static void testSignRecoverablePos() throws AssertFailException{

        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());

        byte[] resultArr = NativeSecp256k1.signRecoverable(data, sec);
        String sigString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( sigString, "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E901" , "testSignRecoverablePos");
    }

    /**
      * This tests sign() for a invalid secretkey
      */
    public static void testSignRecoverableNeg() throws AssertFailException{
        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase());

        byte[] resultArr = NativeSecp256k1.signRecoverable(data, sec);
        String sigString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( sigString, "" , "testSignRecoverableNeg");
    }

    public static void main(String[] args) throws AssertFailException{
        System.out.println("\n libsecp256k1 enabled: " + Secp256k1Context.isEnabled() + "\n");

        assertEquals( Secp256k1Context.isEnabled(), true, "isEnabled" );

        //Test signRecoverable() success/fail
        testSignRecoverablePos();
        testSignRecoverableNeg();

        NativeSecp256k1.cleanup();

        System.out.println(" All recovery tests passed." );

    }
}
