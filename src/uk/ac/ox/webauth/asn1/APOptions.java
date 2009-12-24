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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERObject;


/**
 * Java object definition of the following ASN.1 structure:
 * <pre>
 *   APOptions ::= BIT STRING {
 *       reserved(0),
 *       use-session-key(1),
 *       mutual-required(2)
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
public class APOptions extends ASN1Encodable {
    
    
    private DERBitString bits;
    public boolean reserved0() { return reserved0; }
    private boolean reserved0;
    public boolean use_session_key() { return use_session_key; }
    private boolean use_session_key;
    public boolean mutual_required() { return mutual_required; }
    private boolean mutual_required;
    public boolean reserved3() { return reserved3; }
    private boolean reserved3;
    
    
    public APOptions() {
        bits = new DERBitString(new byte[]{0,0,0,0});
    }
    
    
    public APOptions(DERBitString bits) {
        this.bits = bits;
        byte[] array = bits.getBytes();
        reserved0 = (array[0] > 0);
        use_session_key = (array[1] > 0);
        mutual_required = (array[2] > 0);
        reserved3 = (array[3] > 0);
    }
    
    
    @Override public DERObject toASN1Object() {
        return bits;
    }


    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("APOptions ::= BIT STRING {\n");
        sb.append("     reserved(0) = ").append(reserved0).append("\n");
        sb.append("     use-session-key(1) = ").append(use_session_key).append("\n");
        sb.append("     mutual-required(2) = ").append(mutual_required).append("\n");
        sb.append("     reserved(3) = ").append(reserved3).append("\n");
        sb.append("}");
        return sb.toString();
    }
}
