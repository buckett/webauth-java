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
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;
import javax.security.auth.kerberos.KerberosPrincipal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import static java.util.Calendar.MILLISECOND;


/**
 * Create or parse a KRB_AP_REQ message.
 * <pre>
 * Authenticator ::= [APPLICATION 2] SEQUENCE    {
 *     authenticator-vno[0]          INTEGER,
 *     crealm[1]                     Realm,
 *     cname[2]                      PrincipalName,
 *     cksum[3]                      Checksum OPTIONAL,
 *     cusec[4]                      INTEGER,
 *     ctime[5]                      KerberosTime,
 *     subkey[6]                     EncryptionKey OPTIONAL,
 *     seq-number[7]                 INTEGER OPTIONAL,
 *     authorization-data[8]         AuthorizationData OPTIONAL
 * }
 *
 * KerberosTime ::=   GeneralizedTime -- Specifying UTC time zone (Z)
 * </pre>
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class Authenticator extends ASN1Encodable {
    
    
    private static final int AUTHENTICATOR_APP_TAG = 2;
    private static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    private DERInteger authenticator_vno;
    private DERGeneralString crealm;
    private PrincipalName cname;
    private DERInteger cusec;
    private DERGeneralizedTime ctime;
    private DERInteger seq_number;
    
    
    /**
     * Instantiate an Authenticator.
     * @param   princ   The KerberosPrincipal of the ticket.
     */
    public Authenticator(KerberosPrincipal princ) {
        authenticator_vno = new DERInteger(5);
        crealm = new DERGeneralString(princ.getRealm());
        String name = princ.getName().split("@")[0];
        cname = new PrincipalName(princ.getNameType(), name.split("/"));
        Calendar cal = Calendar.getInstance();
        cusec = new DERInteger(cal.get(MILLISECOND)*1000);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        sdf.setTimeZone(UTC);
        ctime = new DERGeneralizedTime(sdf.format(cal.getTime()));
        // have left seq-number out for now...
    }
    
    
    /**
     * Parse an Authenticator message into an object structure.
     * @param   data    The ASN.1 structure to parse.
     */
    public Authenticator(DERApplicationSpecific data)
            throws IllegalArgumentException, IOException, GeneralSecurityException {
        if(data.getApplicationTag() != AUTHENTICATOR_APP_TAG) {
            throw new IllegalArgumentException("Expected Authenticator ASN.1 APPLICATION tag of 2, got "
                    +data.getApplicationTag()+".");
        }
        ASN1Sequence seq = (ASN1Sequence)data.getObject();
        for(int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject asn1 = (ASN1TaggedObject)seq.getObjectAt(i);
            switch(asn1.getTagNo()) {
                case 0: // authenticator-vno
                    authenticator_vno = (DERInteger)asn1.getObject();
                    if(authenticator_vno.getValue().longValue() != 5) {
                        throw new IllegalArgumentException("The Authenticator authenticator-vno has value "
                                +authenticator_vno.getValue().longValue()+", should be 5.");
                    }
                    break;
                case 1: // crealm
                    crealm = (DERGeneralString)asn1.getObject();
                    break;
                case 2: // cname
                    cname = new PrincipalName((ASN1Sequence)asn1.getObject());
                    break;
                // TODO: finish the other types (not needed at the moment)
                case 3: // cksum
                    System.out.println("Authenticator: got a cksum, not using it.");
                    break;
                case 4: // cusec
                    cusec = (DERInteger)asn1.getObject();
                    break;
                case 5: // ctime
                    ctime = (DERGeneralizedTime)asn1.getObject();
                    break;
                // TODO: finish the other types (not needed at the moment)
                case 6: // subkey
                    System.out.println("Authenticator: got a subkey, not using it.");
                    break;
                case 7: // seq-number
                    seq_number = (DERInteger)asn1.getObject();
                    break;
                // TODO: finish the other types (not needed at the moment)
                case 8: // authorization-data
                    System.out.println("Authenticator: got authorization-data, not using it.");
                    break;
                default:
                    throw new IllegalArgumentException("Got an ASN.1 object with tag "+asn1.getTagNo()+".");
            }
        }
    }
    
    
    @Override public DERObject toASN1Object() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERTaggedObject(true, 0, authenticator_vno));
            v.add(new DERTaggedObject(true, 1, crealm));
            v.add(new DERTaggedObject(true, 2, cname));
            // TODO: finish the other types (not needed at the moment)
            v.add(new DERTaggedObject(true, 4, cusec));
            v.add(new DERTaggedObject(true, 5, ctime));
            // TODO: finish the other types (not needed at the moment)
            if(seq_number != null) { v.add(new DERTaggedObject(true, 7, seq_number)); }
            // TODO: finish the other types (not needed at the moment)
            return new DERApplicationSpecific(AUTHENTICATOR_APP_TAG, new DERSequence(v));
        }
        catch(IOException ioe) { ioe.printStackTrace(); }
        return null;
    }
    
    
    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("Authenticator ::= [APPLICATION 2] SEQUENCE {\n");
        sb.append("    authenticator-vno[0] = ").append(authenticator_vno.getValue()).append("\n");
        sb.append("    crealm[1] = ").append(crealm.getString()).append("\n");
        sb.append("    cname[2] = ").append(cname.toString().replaceAll("\n", "\n    ")).append("\n");
        // TODO: finish the other types and add them here (not needed at the moment)
        sb.append("    cusec[4] = ").append(cusec.getValue()).append("\n");
        sb.append("    ctime[5] = ").append(ctime.getTime()).append("\n");
        // TODO: finish the other types and add them here (not needed at the moment)
        if(seq_number != null) { sb.append("    seq-number[7] = ").append(seq_number.getValue()).append("\n"); }
        // TODO: finish the other types and add them here (not needed at the moment)
        sb.append("}");
        return sb.toString();
    }
}