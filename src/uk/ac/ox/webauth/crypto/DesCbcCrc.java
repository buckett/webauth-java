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
import java.io.InputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;

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
        
        // split out the CRC checksum (4 bytes)
        byte[] checksum = new byte[4];
        System.arraycopy(data, cipher.getBlockSize(), checksum, 0, checksum.length);
        Arrays.fill(data, cipher.getBlockSize(), cipher.getBlockSize()+checksum.length, (byte)0);
        
        // do the CRC check
        // TODO: complete this
        
        // return an ASN.1 object
        InputStream is = new ByteArrayInputStream(data);
        is.skip(cipher.getBlockSize() + checksum.length);
        ASN1InputStream ais = new ASN1InputStream(is);
        
        return (ASN1Encodable)ais.readObject();
    }
    
    
    @Override public byte[] encrypt(ASN1Encodable o) throws IOException, GeneralSecurityException {
        return null;
    }
}