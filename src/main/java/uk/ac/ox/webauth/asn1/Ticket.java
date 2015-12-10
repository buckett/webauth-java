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
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;


/**
 * Java object definition of the following ASN.1 structure:
 * <pre>
 *   Ticket ::= [APPLICATION 1] SEQUENCE {
 *       tkt-vno[0]             INTEGER,
 *       realm[1]               Realm,
 *       sname[2]               PrincipalName,
 *       enc-part[3]            EncryptedData
 *   }
 *
 *   Realm ::= GeneralString
 * </pre>
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class Ticket extends ASN1Encodable {
    
    
    private static final int TICKET_APP_TAG = 1;

    private DERInteger tkt_vno;
    private DERGeneralString realm;
    private PrincipalName sname;
    private EncryptedData enc_part;
    
    
    public Ticket(DERApplicationSpecific data, int keyType, SecretKey key, int keyUsage)
            throws IllegalArgumentException, IOException, GeneralSecurityException {
        if(data.getApplicationTag() != TICKET_APP_TAG) {
            throw new IllegalArgumentException("Expected Ticket ASN.1 APPLICATION tag of 1, got "
                    +data.getApplicationTag()+".");
        }
        ASN1Sequence seq = (ASN1Sequence)data.getObject();
        for(int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject asn1 = (ASN1TaggedObject)seq.getObjectAt(i);
            switch(asn1.getTagNo()) {
                case 0: // tkt-vno
                    tkt_vno = (DERInteger)asn1.getObject();
                    break;
                case 1: // realm
                    realm = (DERGeneralString)asn1.getObject();
                    break;
                case 2: // sname
                    sname = new PrincipalName((ASN1Sequence)asn1.getObject());
                    break;
                case 3: // enc-part
                    enc_part = new EncryptedData((ASN1Sequence)asn1.getObject(), keyType, key, keyUsage);
                    break;
                default:
                    throw new IllegalArgumentException("Got an ASN.1 object with tag "+asn1.getTagNo()+".");
            }
        }
    }
    
    
    @Override public DERObject toASN1Object() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERTaggedObject(true, 0, tkt_vno));
            v.add(new DERTaggedObject(true, 1, realm));
            v.add(new DERTaggedObject(true, 2, sname));
            v.add(new DERTaggedObject(true, 3, enc_part));

            return new DERApplicationSpecific(TICKET_APP_TAG, new DERSequence(v));
        }
        catch(IOException ioe) { ioe.printStackTrace(); }
        return null;
    }


    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Ticket ::= [APPLICATION 1] SEQUENCE {\n");
        sb.append("    tkt-vno[0] = ").append(tkt_vno.getValue()).append("\n");
        sb.append("    realm[1] = ").append(realm.getString()).append("\n");
        sb.append("    sname[2] = ").append(sname.toString().replaceAll("\n", "\n    ")).append("\n");
        sb.append("    enc-part[3] = ").append(enc_part.toString().replaceAll("\n", "\n    ")).append("\n");
        sb.append("}");
        return sb.toString();
    }
}
