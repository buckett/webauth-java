package uk.ac.ox.webauth.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.junit.Assert;
import org.junit.Test;
import uk.ac.ox.webauth.asn1.APOptions;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import static uk.ac.ox.webauth.crypto.Des3CbcSha1Kd.*;

/**
 * Unit tests
 */
public class Des3CbcSha1KdTest {

    public void test_nFold(String data, String input, String correct, int numBits) throws DecoderException {
        Hex hex = new Hex();
        byte[] output = nFold((byte[])hex.decode(input), numBits);
        Assert.assertArrayEquals((byte[])hex.decode(correct), output);
    }


    public void test_DR_DK(String key, String usage, String correct_dr, String correct_dk)
            throws DecoderException, GeneralSecurityException {
        Hex hex = new Hex();
        byte[] input = (byte[])hex.decode(key);
        byte[] constant = (byte[])hex.decode(usage);
        byte[] dr = (byte[])hex.decode(correct_dr);
        byte[] dk = (byte[])hex.decode(correct_dk);
        byte[] output = dr(input, constant);
        Assert.assertArrayEquals(output, dr);
        output = dk(input, constant);
        Assert.assertArrayEquals(output, dk);
    }


    @Test
    public void test() throws Exception {
        // test the nFold with test vectors given in RFC 3961

        /*
        64-fold("012345") =
        64-fold(303132333435) = be072631276b1955
        */
        test_nFold("012345", "303132333435", "be072631276b1955", 64);

        /*
        56-fold("password") =
        56-fold(70617373776f7264) = 78a07b6caf85fa
        */
        test_nFold("password", "70617373776f7264", "78a07b6caf85fa", 56);

        /*
        64-fold("Rough Consensus, and Running Code") =
        64-fold(526f75676820436f6e73656e7375732c20616e642052756e6e696e6720436f6465) = bb6ed30870b7f0e0
        */
        test_nFold("Rough Consensus, and Running Code",
                "526f75676820436f6e73656e7375732c20616e642052756e6e696e6720436f6465", "bb6ed30870b7f0e0", 64);

        /*
        168-fold("password") =
        168-fold(70617373776f7264) = 59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e
        */
        test_nFold("password", "70617373776f7264", "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e", 168);

        /*
        192-fold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY")
        192-fold(4d41535341434856534554545320494e53544954565445204f4620544543484e4f4c4f4759) =
               db3b0d8f0b061e603282b308a50841229ad798fab9540c1b
        */
        test_nFold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
                "4d41535341434856534554545320494e53544954565445204f4620544543484e4f4c4f4759",
                "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b", 192);

        /*
        168-fold("Q") =
        168-fold(51) = 518a54a2 15a8452a 518a54a2 15a8452a 518a54a2 15
        */
        test_nFold("Q", "51", "518a54a215a8452a518a54a215a8452a518a54a215", 168);

        /*
        168-fold("ba") =
        168-fold(6261) = fb25d531 ae897449 9f52fd92 ea9857c4 ba24cf29 7e
        */
        test_nFold("ba", "6261", "fb25d531ae8974499f52fd92ea9857c4ba24cf297e", 168);

        /*
        key:                 dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92
        usage:               0000000155
        DR:                  935079d14490a75c3093c4a6e8c3b049c71e6ee705
        DK:                  925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd
        */
        test_DR_DK("dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92",
                "0000000155",
                "935079d14490a75c3093c4a6e8c3b049c71e6ee705",
                "925179d04591a79b5d3192c4a7e9c289b049c71f6ee604cd");

        /*
        key:                 5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2
        usage:               00000001aa
        DR:                  9f58e5a047d894101c469845d67ae3c5249ed812f2
        DK:                  9e58e5a146d9942a101c469845d67a20e3c4259ed913f207
        */
        test_DR_DK("5e13d31c70ef765746578531cb51c15bf11ca82c97cee9f2",
                "00000001aa",
                "9f58e5a047d894101c469845d67ae3c5249ed812f2",
                "9e58e5a146d9942a101c469845d67a20e3c4259ed913f207");

        /*
        key:                 98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc
        usage:               0000000155
        DR:                  12fff90c773f956d13fc2ca0d0840349dbd39908eb
        DK:                  13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf
        */
        test_DR_DK("98e6fd8a04a4b6859b75a176540b9752bad3ecd610a252bc",
                "0000000155",
                "12fff90c773f956d13fc2ca0d0840349dbd39908eb",
                "13fef80d763e94ec6d13fd2ca1d085070249dad39808eabf");

        /*
        key:                 622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5
        usage:               00000001aa
        DR:                  f8debf05b097e7dc0603686aca35d91fd9a5516a70
        DK:                  f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e
        */
        test_DR_DK("622aec25a2fe2cad7094680b7c64940280084c1a7cec92b5",
                "00000001aa",
                "f8debf05b097e7dc0603686aca35d91fd9a5516a70",
                "f8dfbf04b097e6d9dc0702686bcb3489d91fd9a4516b703e");

        /*
        key:                 d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb
        usage:               6b65726265726f73 ("kerberos")
        DR:                  2270db565d2a3d64cfbfdc5305d4f778a6de42d9da
        DK:                  2370da575d2a3da864cebfdc5204d56df779a7df43d9da43
        */
        test_DR_DK("d3f8298ccb166438dcb9b93ee5a7629286a491f838f802fb",
                "6b65726265726f73",
                "2270db565d2a3d64cfbfdc5305d4f778a6de42d9da",
                "2370da575d2a3da864cebfdc5204d56df779a7df43d9da43");

        /*
        key:                 c1081649ada74362e6a1459d01dfd30d67c2234c940704da
        usage:               0000000155
        DR:                  348056ec98fcc517171d2b4d7a9493af482d999175
        DK:                  348057ec98fdc48016161c2a4c7a943e92ae492c989175f7
        */
        test_DR_DK("c1081649ada74362e6a1459d01dfd30d67c2234c940704da",
                "0000000155",
                "348056ec98fcc517171d2b4d7a9493af482d999175",
                "348057ec98fdc48016161c2a4c7a943e92ae492c989175f7");

        /*
        key:                 5d154af238f46713155719d55e2f1f790dd661f279a7917c
        usage:               00000001aa
        DR:                  a8818bc367dadacbe9a6c84627fb60c294b01215e5
        DK:                  a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1
        */
        test_DR_DK("5d154af238f46713155719d55e2f1f790dd661f279a7917c",
                "00000001aa",
                "a8818bc367dadacbe9a6c84627fb60c294b01215e5",
                "a8808ac267dada3dcbe9a7c84626fbc761c294b01315e5c1");

        /*
        key:                 798562e049852f57dc8c343ba17f2ca1d97394efc8adc443
        usage:               0000000155
        DR:                  c813f88b3be2b2f75424ce9175fbc8483b88c8713a
        DK:                  c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49
        */
        test_DR_DK("798562e049852f57dc8c343ba17f2ca1d97394efc8adc443",
                "0000000155",
                "c813f88b3be2b2f75424ce9175fbc8483b88c8713a",
                "c813f88a3be3b334f75425ce9175fbe3c8493b89c8703b49");

        /*
        key:                 26dce334b545292f2feab9a8701a89a4b99eb9942cecd016
        usage:               00000001aa
        DR:                  f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec
        DK:                  f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d
        */
        test_DR_DK("26dce334b545292f2feab9a8701a89a4b99eb9942cecd016",
                "00000001aa",
                "f58efc6f83f93e55e695fd252cf8fe59f7d5ba37ec",
                "f48ffd6e83f83e7354e694fd252cf83bfe58f7d5ba37ec5d");

        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        KeySpec spec = new DESedeKeySpec(new byte[24]);
        SecretKey secretKey = factory.generateSecret(spec);
        ASN1Encodable apo = new APOptions();
        Des3CbcSha1Kd dcc = new Des3CbcSha1Kd(secretKey, 11);
        byte[] encrypted = dcc.encrypt(apo);
        apo = dcc.decrypt(encrypted);
        System.out.println("Encrypt-decrypt test successful.");
    }
}
