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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEREncodableVector;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;


/**
 * Java object definition of the following ASN.1 structure:
 * <pre>
 *   PrincipalName ::= SEQUENCE {
 *       name-type[0]     INTEGER,
 *       name-string[1]   SEQUENCE OF GeneralString
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
public class PrincipalName extends ASN1Encodable {
    
    
    private DERInteger name_type;
    private ASN1Sequence name_string;
    
    
    /**
     * Instantiate a PrincipalName.
     * @param   type    The type of this principal name.
     * @param   name    An array of strings making up the name.
     */
    public PrincipalName(int type, String[] name) {
        name_type = new DERInteger(type);
        DEREncodableVector v = new DEREncodableVector();
        for(String component : name) {
            v.add(new DERGeneralString(component));
        }
        name_string = new DERSequence(v);
    }
    
    
    public PrincipalName(ASN1Sequence seq) throws IllegalArgumentException, IOException {
        for(int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject asn1 = (ASN1TaggedObject)seq.getObjectAt(i);
            switch(asn1.getTagNo()) {
                case 0: // name-type
                    name_type = (DERInteger)asn1.getObject();
                    break;
                case 1: // name-string
                    name_string = (ASN1Sequence)asn1.getObject();
                    break;
                default:
                    throw new IllegalArgumentException("Got an ASN.1 object with tag "+asn1.getTagNo()+".");
            }
        }
    }
    
    
    @Override public DERObject toASN1Object() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERTaggedObject(true, 0, name_type));
        v.add(new DERTaggedObject(true, 1, name_string));
        return new DERSequence(v);
    }


    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("PrincipalName ::= SEQUENCE {\n");
        sb.append("    name-type[0] = ").append(name_type.getValue()).append("\n");
        sb.append("    name-string[1] = ");
        for(int i = 0; i < name_string.size(); i++) {
            sb.append("'").append( ((DERGeneralString)name_string.getObjectAt(i)).getString() ).append("' ");
        }
        sb.append("\n}");
        return sb.toString();
    }
}
