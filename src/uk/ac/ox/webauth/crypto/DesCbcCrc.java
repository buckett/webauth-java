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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import uk.ac.ox.webauth.asn1.APOptions;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;


/**
 * Class implementing Kerberos encryption type 1, des-cbc-crc, as described in
 * section 6.2.3 of RFC 3961.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class DesCbcCrc extends EType {

    private static final SecureRandom rand = new SecureRandom();
    private static final int[] CRC_TABLE = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
        0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
        0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
        0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
        0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
        0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
        0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
        0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
        0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
        0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
        0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
        0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
        0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
        0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
        0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
        0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
        0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
        0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
        0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
        0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
        0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
        0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
        0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
        0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
        0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
        0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
        0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04,
        0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
        0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
        0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
        0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
        0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
        0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
        0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
        0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
        0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };

    private SecretKey key;
    

    public DesCbcCrc(SecretKey key) {
        this.key = key;
    }
    
    
    /**
     * From RFC 3961:
     * <pre>
     *   +-----------+----------+---------+-----+
     *   |confounder | checksum | msg-seq | pad |
     *   +-----------+----------+---------+-----+
     * </pre>
     */
    @Override public ASN1Encodable decrypt(byte[] cipherData) throws IOException, GeneralSecurityException {
        // decrypt the data
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(key.getEncoded());
        cipher.init(DECRYPT_MODE, key, iv);
        byte[] data = cipher.doFinal(cipherData);
        
        // split out the CRC checksum (4 bytes) and check it
        byte[] checksum = new byte[4];
        System.arraycopy(data, cipher.getBlockSize(), checksum, 0, checksum.length);
        Arrays.fill(data, cipher.getBlockSize(), cipher.getBlockSize()+checksum.length, (byte)0);
        if(!Arrays.equals(checksum, modifiedCRC32(data))) {
            throw new GeneralSecurityException("Checksum failure.");
        }
        
        // return an ASN.1 object
        InputStream is = new ByteArrayInputStream(data);
        is.skip(cipher.getBlockSize() + checksum.length);
        ASN1InputStream ais = new ASN1InputStream(is);
        
        return (ASN1Encodable)ais.readObject();
    }
    
    
    @Override public byte[] encrypt(ASN1Encodable o) throws IOException, GeneralSecurityException {
        // setup the Cipher so we can get the block size
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(key.getEncoded());
        cipher.init(ENCRYPT_MODE, key, iv);
        int blockSize = cipher.getBlockSize();

        // set up the byte array with data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] confounder = new byte[blockSize];
        synchronized(rand) { rand.nextBytes(confounder); }
        baos.write(confounder);
        
        // write empty data in place of the checksum
        byte[] checksum = new byte[4];
        baos.write(checksum);

        // write the message sequence
        baos.write(o.getDEREncoded());

        // PKCS7 padding
        byte[] pad = new byte[blockSize - (baos.size() % blockSize)];
        Arrays.fill(pad, (byte)pad.length);
        baos.write(pad);
        byte[] data = baos.toByteArray();
        
        // calculate the checksum
        checksum = modifiedCRC32(data);
        System.arraycopy(checksum, 0, data, cipher.getBlockSize(), checksum.length);
        
        // now encrypt and return the data
        return cipher.doFinal(data);
    }
    
    
    private static byte[] modifiedCRC32(byte[] data) throws IOException {
        int crc = 0;
        for (int i = 0; i < data.length; i++) {
            crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ data[i]) & 0xff];
        }
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i] = (byte)((crc >>> (i * 8)) & 0xff);
        }
        return output;
    }
    
    
    public static void main(String[] args) throws Exception {
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
    
    
    private static void test_modifiedCRC32(String hexData, String hexAnswer) throws Exception {
        System.out.println("Testing modified crc32 algorithm with data: "+hexData);
        System.out.println("Correct answer: "+hexAnswer);
        String answer = new String(Hex.encodeHex(modifiedCRC32(Hex.decodeHex(hexData.toCharArray()))));
        System.out.println("Answer:         "+answer);
        if(hexAnswer.equalsIgnoreCase(answer)) { System.out.println("SUCCESS!"); }
        else { System.out.println("FAILURE!"); }
    }
}