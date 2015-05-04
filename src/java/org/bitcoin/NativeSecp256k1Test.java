package org.bitcoin;

import com.google.common.io.BaseEncoding;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;

public class NativeSecp256k1Test {

    public static void main(String[] args) throws AssertFailException{

      System.out.println("\n libsecp256k1 enabled: " + NativeSecp256k1.enabled + "\n");

      if( NativeSecp256k1.enabled ) {

        boolean result = false;

        //Case 1 - PASSING
        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sig = BaseEncoding.base16().lowerCase().decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase());
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase()); 

        result = NativeSecp256k1.verify( data, sig, pub );
        assertEquals( result, true , "Case 1");

        //Case 2 - FAILING
        data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91".toLowerCase()); //sha256hash of "testing"
        sig = BaseEncoding.base16().lowerCase().decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase());
        pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase()); 

        result = NativeSecp256k1.verify( data, sig, pub );
        assertEquals( result, false , "Case 2");

        //Case 3 - PASSING
        pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase()); 
        result = NativeSecp256k1.pubKeyVerify( pub );
        assertEquals( result, true , "Case 3");

        //Case 4 - FAILING
        pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C41".toLowerCase()); 
        result = NativeSecp256k1.pubKeyVerify( pub );
        assertEquals( result, false , "Case 4");

        //Case 5 - PASSING
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase()); 
        result = NativeSecp256k1.secKeyVerify( sec );
        assertEquals( result, true , "Case 5");

        //Case 6 - FAILING
        sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase()); 
        result = NativeSecp256k1.secKeyVerify( sec );
        assertEquals( result, false , "Case 6");

        //Case 7 - PASSING
        sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase()); 

        byte[] resultArr = NativeSecp256k1.computePubkey( sec , 0);
        String pubkeyString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( pubkeyString , "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6" , "Case 7");

        resultArr = NativeSecp256k1.computePubkey( sec , 1);
        pubkeyString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( pubkeyString, "02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D" , "Case 7 Compressed");

        //Case 8 - FAILING
        sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase()); 

        resultArr = NativeSecp256k1.computePubkey( sec , 0);
        pubkeyString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( pubkeyString, "" , "Case 8");

        resultArr = NativeSecp256k1.computePubkey( sec , 1);
        pubkeyString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( pubkeyString, "" , "Case 8 Compressed");

        //Case 9 - PASSING
        data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing" 
        sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());  

        resultArr = NativeSecp256k1.sign(data, sec);
        String sigString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( sigString, "30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9" , "Case 9");

        //Case 10 - FAILING
        data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing" 
        sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase()); 

        resultArr = NativeSecp256k1.sign(data, sec);
        sigString = javax.xml.bind.DatatypeConverter.printHexBinary(resultArr);
        assertEquals( sigString, "" , "Case 10");

        System.out.println(" All tests passed." );

      }
    }

    private static void assertEquals( boolean val, boolean val2, String message ) throws AssertFailException{
      if( val != val2 ) 
        throw new AssertFailException("FAIL: " + message);
      else
        System.out.println("PASS: " + message);
    }

    private static void assertEquals( String val, String val2, String message ) throws AssertFailException{
      if( !val.equals(val2) ) 
        throw new AssertFailException("FAIL: " + message);
      else
        System.out.println("PASS: " + message);
    }

    private static class AssertFailException extends Exception {
      public AssertFailException(String message) {
        super( message );
      }
    }
}
