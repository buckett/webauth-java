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
package uk.ac.ox.webauth.asn1;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import uk.ac.ox.webauth.crypto.Des3CbcSha1Kd;
import uk.ac.ox.webauth.crypto.EType;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;


/**
 * Java object definition of the following ASN.1 structure:
 * <pre>
 *   EncryptedData ::= SEQUENCE {
 *       etype[0]     INTEGER, -- EncryptionType
 *       kvno[1]      INTEGER OPTIONAL,
 *       cipher[2]    OCTET STRING -- ciphertext
 *   }
 * </pre>
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class EncryptedData extends ASN1Encodable {
    
    
    private DERInteger etype;
    private DERInteger kvno;
    private ASN1OctetString cipher;
    private ASN1Encodable decrypted;
    public ASN1Encodable decrypted() { return decrypted; }
    public void decrypted(ASN1Encodable e) { this.decrypted = e; }
    
    
    public EncryptedData(ASN1Sequence seq, int keyType, SecretKey key, int keyUsage)
            throws IllegalArgumentException, IOException, GeneralSecurityException {
        EType crypto = null;
        for(int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject asn1 = (ASN1TaggedObject)seq.getObjectAt(i);
            switch(asn1.getTagNo()) {
                case 0: // etype
                    etype = (DERInteger)asn1.getObject();
                    break;
                case 1: // kvno
                    kvno = (DERInteger)asn1.getObject();
                    break;
                case 2: // cipher
                    cipher = (ASN1OctetString)asn1.getObject();
                    if(key != null) {
                        if(keyType == 0) { keyType = etype.getValue().intValue(); }
                        crypto = cryptoInstance(keyType, key, keyUsage);
                        decrypted = crypto.decrypt(cipher.getOctets());
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Got an ASN.1 object with tag "+asn1.getTagNo()+".");
            }
        }
    }
    
    
    /**
     * Static method to create an EncryptedData instance to keep it separate
     * from the constructor of this class.
     * @param   etype   Kerberos encryption type.
     * @param   key     The key to encrypt with.
     * @param   usage   The usage number to use when encrypting.
     * @param   o       The ASN1Encodable to encrypt.
     * @return  An EncryptedData instance.
     */
    public static EncryptedData encrypt(int etype, SecretKey key, int usage, ASN1Encodable o)
            throws IOException, GeneralSecurityException {
        return new EncryptedData(etype, key, usage, o);
    }
    
    
    private EncryptedData(int etype, SecretKey key, int usage, ASN1Encodable o)
            throws IOException, GeneralSecurityException {
        this.etype = new DERInteger(etype);
        decrypted = o;
        EType crypto = cryptoInstance(etype, key, usage);
        cipher = new DEROctetString(crypto.encrypt(o));
    }
    
    
    @Override public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, etype));
        if(kvno != null) { v.add(new DERTaggedObject(true, 1, kvno)); }
        v.add(new DERTaggedObject(true, 2, cipher));
        return new DERSequence(v);
    }
    
    
    private static EType cryptoInstance(int type, SecretKey key, int keyUsage)
            throws IllegalArgumentException, IOException, GeneralSecurityException {
        EType etype = null;
        switch(type) {
            /* Disabled since it's not complete.
            case 1:     // des-cbc-crc
                etype = new DesCbcCrc(cipher, key);
                System.out.println("Using des-cbc-crc etype.");
                break;
            */
            /* TODO: finish additional decryption methods
            case 3:     // des-cbc-md5
                
                break;
            */
            case 16:    // des3-cbc-sha1-kd
                etype = new Des3CbcSha1Kd(key, keyUsage);
                break;
            default:
                throw new IllegalArgumentException("Unknown Kerberos crypto type: "+type+".");
        }
        return etype;
    }
    
    
    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("EncryptedData ::= SEQUENCE {\n");
        sb.append("    etype[0] = ").append(etype.getValue()).append("\n");
        sb.append("    kvno[1] = ").append( ((kvno == null) ? "" : kvno.getValue()) ).append("\n");
        sb.append("    cipher[2] = ");
        if(decrypted == null) {
            sb.append("[Encrypted octet string, don't have the key so can't decrypt. Length: ")
                    .append(cipher.getOctets().length)
                    .append(" bytes.]");
        }
        else {
            sb.append("Encrypted octet string. Decrypted data: ")
                    .append(decrypted.toString().replaceAll("\n", "\n    "));
        }
        sb.append("\n}");
        return sb.toString();
    }
}

