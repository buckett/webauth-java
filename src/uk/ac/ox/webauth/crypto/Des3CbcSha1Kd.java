/*
 * Webauth Java - Java implementation of the University of Stanford WebAuth
 * protocol.
 *
 * Copyright (C) 2006 University of Oxford
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
package uk.ac.ox.webauth.crypto;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;


/**
 * Class implementing Kerberos encryption type 16, des3-cbc-sha1-kd, as
 * described in section 6.3 of RFC 3961.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class Des3CbcSha1Kd extends EType {
    

    private static final IvParameterSpec IV = new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0});
    private static final SecureRandom rand = new SecureRandom();

    private SecretKey key;
    private int keyUsage;
    
    
    public Des3CbcSha1Kd(SecretKey key, int keyUsage) {
        this.key = key;
        this.keyUsage = keyUsage;
    }
    
    
    @Override public ASN1Encodable decrypt(byte[] cipherData) throws IOException, GeneralSecurityException {
        // derive our decryption and hmac keys as per RFC 3961
        // first work out the "well known constant"s for the different keys
        byte[] wkcKe = new byte[5];
        wkcKe[0] = (byte)((keyUsage>>24) & 0xFF);
        wkcKe[1] = (byte)((keyUsage>>16) & 0xFF);
        wkcKe[2] = (byte)((keyUsage>>8) & 0xFF);
        wkcKe[3] = (byte)(keyUsage & 0xFF);
        wkcKe[4] = (byte)0xAA;
        byte[] wkcKi = (byte[])wkcKe.clone();
        wkcKi[4] = (byte)0x55;

        // then make the keys
        // RFC 3961: Derived Key = DK(Base Key, Well-Known Constant)
        SecretKey ke = new SecretKeySpec(dk(key.getEncoded(), wkcKe), "DESede");
        SecretKey ki = new SecretKeySpec(dk(key.getEncoded(), wkcKi), "DESede");
        
        // set up the HMAC object so we can get the length
        Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
        hmacSHA1.init(ki);
        int hmacLength = hmacSHA1.getMacLength();

        // first split the checksum off the data
        InputStream is = new ByteArrayInputStream(cipherData);
        byte[] data = new byte[cipherData.length-hmacLength];
        if(is.read(data) != data.length) { throw new IOException("Couldn't read all the encrypted data."); }
        byte[] checksum = new byte[hmacLength];
        if(is.read(checksum) != checksum.length) { throw new IOException("Couldn't read all the checksum data."); }
        
        // then decrypt the data
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(DECRYPT_MODE, ke, IV);
        byte[] decrypted = cipher.doFinal(data);
        
        // check the HMAC
        byte[] newChecksum = hmacSHA1.doFinal(decrypted);
        if(!Arrays.equals(checksum, newChecksum)) {
            throw new GeneralSecurityException("Checksum failure.");
            //System.out.println("Checksum failed.");
        }
        
        // throw away the confounder and then return an ASN.1 encodable object
        is = new ByteArrayInputStream(decrypted);
        is.skip(cipher.getBlockSize());
        ASN1InputStream ais = new ASN1InputStream(is);
        return (ASN1Encodable)ais.readObject();
    }
    
    
    @Override public byte[] encrypt(ASN1Encodable o) throws IOException, GeneralSecurityException {
        // derive our decryption and hmac keys as per RFC 3961
        // first work out the "well known constant"s for the different keys
        byte[] wkcKe = new byte[5];
        wkcKe[0] = (byte)((keyUsage>>24) & 0xFF);
        wkcKe[1] = (byte)((keyUsage>>16) & 0xFF);
        wkcKe[2] = (byte)((keyUsage>>8) & 0xFF);
        wkcKe[3] = (byte)(keyUsage & 0xFF);
        wkcKe[4] = (byte)0xAA;
        byte[] wkcKi = (byte[])wkcKe.clone();
        wkcKi[4] = (byte)0x55;

        // then make the keys
        // RFC 3961: Derived Key = DK(Base Key, Well-Known Constant)
        SecretKey ke = new SecretKeySpec(dk(key.getEncoded(), wkcKe), "DESede");
        SecretKey ki = new SecretKeySpec(dk(key.getEncoded(), wkcKi), "DESede");
        
        // setup the Cipher so we can get the block size
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(ENCRYPT_MODE, ke, IV);
        int blockSize = cipher.getBlockSize();

        // set up the byte array with data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] confounder = new byte[blockSize];
        synchronized(rand) { rand.nextBytes(confounder); }
        baos.write(confounder);
        baos.write(o.getDEREncoded());

        // PKCS7 padding
        byte[] pad = new byte[blockSize - (baos.size() % blockSize)];
        Arrays.fill(pad, (byte)pad.length);
        baos.write(pad);
        byte[] data = baos.toByteArray();
        
        // calculate the checksum
        Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
        hmacSHA1.init(ki);
        byte[] checksum = hmacSHA1.doFinal(data);
        
        // now encrypt the data
        baos = new ByteArrayOutputStream();
        baos.write(cipher.doFinal(data));
        baos.write(checksum);
        
        return baos.toByteArray();
    }

        
    /**
     * From RFC 3961:
     * DK(Key, Constant) = random-to-key(DR(Key, Constant))
     */
    private static byte[] dk(byte[] key, byte[] constant) throws GeneralSecurityException {
        // TODO: currently not checking weak and semi-weak keys as per RFC 3961!!!
        return randomToKey(dr(key, constant));
    }
    
    
    /**
     * From RFC 3961:
     *
     * 6.3.1.  Triple DES Key Production (random-to-key, string-to-key)
     *
     * The 168 bits of random key data are converted to a protocol key value
     * as follows.  First, the 168 bits are divided into three groups of 56
     * bits, which are expanded individually into 64 bits as follows:
     *
     * <pre>
     * DES3random-to-key:
     *       1  2  3  4  5  6  7  p
     *       9 10 11 12 13 14 15  p
     *      17 18 19 20 21 22 23  p
     *      25 26 27 28 29 30 31  p
     *      33 34 35 36 37 38 39  p
     *      41 42 43 44 45 46 47  p
     *      49 50 51 52 53 54 55  p
     *      56 48 40 32 24 16  8  p
     * </pre>
     *
     * The "p" bits are parity bits computed over the data bits.  The output
     * of the three expansions, each corrected to avoid "weak" and "semi-
     * weak" keys as in section 6.2, are concatenated to form the protocol
     * key value.
     */
    private static byte[] randomToKey(byte[] rawKey) {
        if(rawKey.length != 21) { throw new IllegalArgumentException("The raw key must be 168 bits (21 bytes)."); }
        
        // first expand and calculate parity for each of the three groups
        byte[] group1 = expandAndParity(rawKey, 0);
        byte[] group2 = expandAndParity(rawKey, 7);
        byte[] group3 = expandAndParity(rawKey, 14);
        
        // then put them together into one key and return that
        byte[] key = new byte[24];
        System.arraycopy(group1, 0, key, 0, group1.length);
        System.arraycopy(group2, 0, key, 8, group2.length);
        System.arraycopy(group3, 0, key, 16, group3.length);
        return key;
    }
    
    
    private static byte[] expandAndParity(byte[] in, int start) {
        // first work out what the last byte is
        byte[] out = new byte[8];
        System.arraycopy(in, start, out, 0, 7);
        int lastByte = 0;
        for(int last = 0; last < 7; last++) {
            if((out[last] & 0x01) == 1) {
                lastByte |= (1 << (last+1));
            }
        }
        out[7] = (byte)lastByte;
        
        // now work out the parity for each byte
        for(int i = 0; i < out.length; i++) {
            byte current = out[i];
            int bits = 0;
            for(int bit = 1; bit < 8; bit++) {
                current >>= 1;
                if((current & 0x01) > 0) { bits++; }
            }
            // set the parity bit if we get an even number of set bits
            if((bits % 2) == 0) { out[i] |= 0x01; }
            else { out[i] &= 0xFE; }
        }
        
        return out;
    }
    
    
    /**
     * From RFC 3961:
     * DR(Key, Constant) = k-truncate(E(Key, Constant, initial-cipher-state))
     *
     * Here DR is the random-octet generation function described below, and
     * DK is the key-derivation function produced from it.  In this
     * construction, E(Key, Plaintext, CipherState) is a cipher, Constant is
     * a well-known constant determined by the specific usage of this
     * function, and k-truncate truncates its argument by taking the first k
     * bits.  Here, k is the key generation seed length needed for the
     * encryption system.
     *
     * The output of the DR function is a string of bits; the actual key is
     * produced by applying the cryptosystem's random-to-key operation on
     * this bitstring.
     *
     * If the Constant is smaller than the cipher block size of E, then it
     * must be expanded with n-fold() so it can be encrypted.  If the output
     * of E is shorter than k bits, it is fed back into the encryption as
     * many times as necessary.  The construct is as follows (where |
     * indicates concatentation):
     *
     *    K1 = E(Key, n-fold(Constant), initial-cipher-state)
     *    K2 = E(Key, K1, initial-cipher-state)
     *    K3 = E(Key, K2, initial-cipher-state)
     *    K4 = ...
     *
     *    DR(Key, Constant) = k-truncate(K1 | K2 | K3 | K4 ...)
     */
    private static byte[] dr(byte[] key, byte[] constant) throws GeneralSecurityException {
        // first make a DES3 key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
        KeySpec spec = new DESedeKeySpec(key);
        SecretKey secretKey = factory.generateSecret(spec);
        
        // initialise the cipher to use
        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        cipher.init(ENCRYPT_MODE, secretKey, IV);
        
        // ensure the constant is not smaller than the blocksize
        if(constant.length < cipher.getBlockSize()) {
            constant = nFold(constant, cipher.getBlockSize()*8);
        }
        
        // now encrypt until we have at least 21 bytes, the length of a DES3 key
        byte[] input = constant;
        byte[] kn = new byte[0];
        do {
            byte[] newKn = cipher.doFinal(input);
            byte[] oldKn = kn;
            kn = new byte[oldKn.length + newKn.length];
            System.arraycopy(oldKn, 0, kn, 0, oldKn.length);
            System.arraycopy(newKn, 0, kn, oldKn.length, newKn.length);
            input = newKn;
        } while(kn.length < 21);
        
        // make sure we are returning exactly 21 bytes
        if(kn.length != 21) {
            byte[] newKn = new byte[21];
            System.arraycopy(kn, 0, newKn, 0, 21);
            kn = newKn;
        }
        
        return kn;
    }
    

    /**
     * From RFC 3961:
     *
     * We first define a primitive called n-folding, which takes a
     * variable-length input block and produces a fixed-length output
     * sequence.  The intent is to give each input bit approximately
     * equal weight in determining the value of each output bit.  Note
     * that whenever we need to treat a string of octets as a number, the
     * assumed representation is Big-Endian -- Most Significant Byte
     * first.
     *
     * To n-fold a number X, replicate the input value to a length that
     * is the least common multiple of n and the length of X.  Before
     * each repetition, the input is rotated to the right by 13 bit
     * positions.  The successive n-bit chunks are added together using
     * 1's-complement addition (that is, with end-around carry) to yield
     * a n-bit result....
     * @param   in      The incoming bytes.
     * @param   nBytesOut    The number of bits to fold the in bytes into.
     * @return  The in bytes folded into a byte array that is nBytesOut bits wide.
     */
    private static byte[] nFold(byte[] in, int nBitsOut) {
        if((nBitsOut % 8) != 0) {
            throw new IllegalArgumentException("nBytesOut must be a multiple of 8");
        }
        
        // Some of this source is adapted from the MIT Kerberos v5 1.4.3 source.
        
        /* the code below is more readable if I make these bytes instead of bits */
        int nBytesIn = in.length;
        int nBitsIn = nBytesIn * 8;
        int nBytesOut = nBitsOut/8;
    
        /* first compute lcm(n,k) */
        int a = nBytesOut;
        int b = nBytesIn;
        int c;
        while(b != 0) {
            c = b;
            b = a % b;
            a = c;
        }
        int lcm = (nBytesOut * nBytesIn) / a;
    
        /* now do the real work */
        byte[] workBuffer = new byte[lcm];
        
        // fill with shifted input
        byte[] shifted = (byte[])in.clone();
        for(int i = 0; i < (lcm/shifted.length); i++) {
            System.arraycopy(shifted, 0, workBuffer, i*shifted.length, shifted.length);
            byte[] newShifted = new byte[shifted.length];
            for(int sbyteIndex = 0; sbyteIndex < shifted.length; sbyteIndex++) {
                int lowByte = (sbyteIndex - 2 + shifted.length) % shifted.length;
                int highByte = (sbyteIndex - 1 + shifted.length) % shifted.length;
                newShifted[sbyteIndex] = (byte)((shifted[lowByte]<<3) | ((shifted[highByte]>>5) & 0x07));
            }
            shifted = newShifted;
        }
        
        // 1's complement add the shifted blocks together
        byte[] out = new byte[nBytesOut];
        System.arraycopy(workBuffer, 0, out, 0, nBytesOut);
        for(int i = 1; i < (lcm/nBytesOut); i++) {
            int workOffset = i * nBytesOut;
            int carry = 0;
            for(int j = nBytesOut-1; j >= 0; j--) {
                int result = (((int)out[j])&0xFF) + (((int)workBuffer[workOffset+j])&0xFF) + (carry&0xFF);
                out[j] = (byte)result;
                carry = (result >>> 8) & 0x01;
            }
            out[nBytesOut-1] = (byte)(((int)out[nBytesOut-1]) + carry);
        }
        return out;
    }
    
    
    private static void test_nFold(String data, String input, String correct, int numBits) throws DecoderException {
        Hex hex = new Hex();
        byte[] output = nFold((byte[])hex.decode(input), numBits);
        if(Arrays.equals((byte[])hex.decode(correct), output)) {
            System.out.println("PASSED: "+numBits+"-fold of string '"+data+"'.");
        }
        else { System.err.println("FAILED: "+numBits+"-fold of string '"+data+"'."); }
    }
    
    
    private static void test_DR_DK(String key, String usage, String correct_dr, String correct_dk)
            throws DecoderException, GeneralSecurityException {
        Hex hex = new Hex();
        byte[] input = (byte[])hex.decode(key);
        byte[] constant = (byte[])hex.decode(usage);
        byte[] dr = (byte[])hex.decode(correct_dr);
        byte[] dk = (byte[])hex.decode(correct_dk);
        System.out.println("Testing DR/DK, usage: "+usage+", key: "+key);
        byte[] output = dr(input, constant);
        if(Arrays.equals(output, dr)) { System.out.println("PASSED: DR"); }
        else { System.err.println("FAILED: DR"); }
        output = dk(input, constant);
        if(Arrays.equals(output, dk)) { System.out.println("PASSED: DK"); }
        else { System.err.println("FAILED: DK"); }
    }


    public static void main(String[] args) throws Exception {
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
    }
}