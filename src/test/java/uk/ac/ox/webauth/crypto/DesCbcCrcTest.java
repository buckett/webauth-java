package uk.ac.ox.webauth.crypto;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.junit.Assert;
import org.junit.Test;
import uk.ac.ox.webauth.asn1.APOptions;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.spec.KeySpec;

import static uk.ac.ox.webauth.crypto.DesCbcCrc.modifiedCRC32;

/**
 * Unit tests
 */
public class DesCbcCrcTest {

    @Test
    public void test() throws Exception {
        /* mod-crc-32 tests from RFC 3961 section A.5:
           mod-crc-32("foo") =                                     33 bc 32 73
           mod-crc-32("test0123456789") =                          d6 88 3e b8
           mod-crc-32("MASSACHVSETTS INSTITVTE OF TECHNOLOGY") =   f7 80 41 e3
           mod-crc-32(8000) =                                      4b 98 83 3b
           mod-crc-32(0008) =                                      32 88 db 0e
           mod-crc-32(0080) =                                      20 83 b8 ed
           mod-crc-32(80) =                                        20 83 b8 ed
           mod-crc-32(80000000) =                                  3b b6 59 ed
           mod-crc-32(00000001) =                                  96 30 07 77
        */
        test_modifiedCRC32(new String(Hex.encodeHex("foo".getBytes())), "33bc3273");
        test_modifiedCRC32(new String(Hex.encodeHex("test0123456789".getBytes())), "d6883eb8");
        test_modifiedCRC32(new String(Hex.encodeHex("MASSACHVSETTS INSTITVTE OF TECHNOLOGY".getBytes())), "f78041e3");
        test_modifiedCRC32("8000", "4b98833b");
        test_modifiedCRC32("0008", "3288db0e");
        test_modifiedCRC32("0080", "2083b8ed");
        test_modifiedCRC32("80", "2083b8ed");
        test_modifiedCRC32("80000000", "3bb659ed");
        test_modifiedCRC32("00000001", "96300777");
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DES");
        KeySpec spec = new DESKeySpec(new byte[8]);
        SecretKey secretKey = factory.generateSecret(spec);
        ASN1Encodable apo = new APOptions();
        DesCbcCrc dcc = new DesCbcCrc(secretKey);
        byte[] encrypted = dcc.encrypt(apo);
        apo = dcc.decrypt(encrypted);
        System.out.println("Encrypt-decrypt test successful.");
    }

    public void test_modifiedCRC32(String hexData, String hexAnswer) throws Exception {
        System.out.println("Testing modified crc32 algorithm with data: "+hexData);
        System.out.println("Correct answer: "+hexAnswer);
        String answer = new String(Hex.encodeHex(modifiedCRC32(Hex.decodeHex(hexData.toCharArray()))));
        System.out.println("Answer:         "+answer);
        Assert.assertEquals(hexAnswer, answer);
    }
}
