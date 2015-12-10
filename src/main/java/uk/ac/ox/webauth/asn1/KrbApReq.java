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
import javax.security.auth.kerberos.KerberosTicket;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;


/**
 * Create or parse a KRB_AP_REQ message.
 * <pre>
 *   AP-REQ ::= [APPLICATION 14] SEQUENCE {
 *       pvno[0]                 INTEGER,
 *       msg-type[1]             INTEGER,
 *       ap-options[2]           APOptions,
 *       ticket[3]               Ticket,
 *       authenticator[4]        EncryptedData
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
public class KrbApReq extends ASN1Encodable {
    
    
    private static final int KRB_AP_REQ_APP_TAG = 14;
    private static final int KRB_AP_REQ_USAGE = 11;
    
    private DERInteger pvno;
    private DERInteger msg_type;
    private APOptions ap_options;
    private Ticket ticket;
    private EncryptedData authenticator;
    
    
    /**
     * Instantiate a KRB_AP_REQ message.
     * @param   krb5Tkt The krb5 ticket to use to send this request.
     */
    public KrbApReq(KerberosTicket krb5Tkt) throws IOException, GeneralSecurityException {
        pvno = new DERInteger(5);
        msg_type = new DERInteger(KRB_AP_REQ_APP_TAG);
        ap_options = new APOptions();
        ASN1InputStream ais = new ASN1InputStream(krb5Tkt.getEncoded());
        ticket = new Ticket((DERApplicationSpecific)ais.readObject(), 0, null, 0);
        
        Authenticator auth = new Authenticator(krb5Tkt.getClient());
        authenticator = EncryptedData.encrypt(krb5Tkt.getSessionKeyType(), krb5Tkt.getSessionKey(), KRB_AP_REQ_USAGE,
                auth);
    }
    
    
    /**
     * Parse a KRB_AP_REQ message into an object structure.
     * @param   data        The ASN.1 structure to parse.
     * @param   keyType     Which type of Kerberos encryption this key is used for.
     * @param   sessionKey  The session key to decrypt with.
     */
    public KrbApReq(DERApplicationSpecific data, int keyType, SecretKey sessionKey)
            throws IllegalArgumentException, IOException, GeneralSecurityException {
        if(data.getApplicationTag() != KRB_AP_REQ_APP_TAG) {
            throw new IllegalArgumentException("Expected AP-REQ ASN.1 APPLICATION tag of 14, got "
                    +data.getApplicationTag()+".");
        }
        ASN1Sequence seq = (ASN1Sequence)data.getObject();
        for(int i = 0; i < seq.size(); i++) {
            ASN1TaggedObject asn1 = (ASN1TaggedObject)seq.getObjectAt(i);
            switch(asn1.getTagNo()) {
                case 0: // pvno
                    pvno = (DERInteger)asn1.getObject();
                    if(pvno.getValue().longValue() != 5) {
                        throw new IllegalArgumentException("The KRB_AP_REQ pvno has value "
                                +pvno.getValue().longValue()+", should be 5.");
                    }
                    break;
                case 1: // msg-type
                    msg_type = (DERInteger)asn1.getObject();
                    if(msg_type.getValue().longValue() != KRB_AP_REQ_APP_TAG) {
                        throw new IllegalArgumentException("The KRB_AP_REQ msg-type has value "
                                +msg_type.getValue().longValue()+", should be "+KRB_AP_REQ_APP_TAG+".");
                    }
                    break;
                case 2: // ap-options
                    ap_options = new APOptions((DERBitString)asn1.getObject());
                    break;
                case 3: // ticket
                    // depends on ap-options having been parsed first
                    if(ap_options.use_session_key()) {
                        // use a key usage number of 11, for KRB_AP_REQ messages
                        ticket = new Ticket((DERApplicationSpecific)asn1.getObject(), keyType, sessionKey,
                                KRB_AP_REQ_USAGE);
                    }
                    else { ticket = new Ticket((DERApplicationSpecific)asn1.getObject(), 0, null, 0); }
                    break;
                case 4: // authenticator
                    // use a key usage number of 11, for KRB_AP_REQ messages
                    authenticator = new EncryptedData((ASN1Sequence)asn1.getObject(), keyType, sessionKey,
                            KRB_AP_REQ_USAGE);
                    if(authenticator.decrypted() != null) {
                        ASN1Encodable a = authenticator.decrypted();
                        authenticator.decrypted(new Authenticator((DERApplicationSpecific)a));
                    }
                    break;
                default:
                    throw new IllegalArgumentException("Got an ASN.1 object with tag "+asn1.getTagNo()+".");
            }
        }
    }
    
    
    @Override public DERObject toASN1Object() {
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERTaggedObject(true, 0, pvno));
            v.add(new DERTaggedObject(true, 1, msg_type));
            v.add(new DERTaggedObject(true, 2, ap_options));
            v.add(new DERTaggedObject(true, 3, ticket));
            v.add(new DERTaggedObject(true, 4, authenticator));
            return new DERApplicationSpecific(KRB_AP_REQ_APP_TAG, new DERSequence(v));
        }
        catch(IOException ioe) { ioe.printStackTrace(); }
        return null;
    }
    
    
    @Override public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("AP-REQ ::= [APPLICATION 14] SEQUENCE {\n");
        sb.append("    pvno[0] = ").append(pvno.getValue()).append("\n");
        sb.append("    msg-type[1] = ").append(msg_type.getValue()).append("\n");
        sb.append("    ap-options[2] = ").append(ap_options.toString().replaceAll("\n", "\n    ")).append("\n");
        sb.append("    ticket[3] = ").append(ticket.toString().replaceAll("\n", "\n    ")).append("\n");
        sb.append("    authenticator[4] = ").append(authenticator.toString().replaceAll("\n", "\n    ")).append("\n");
        sb.append("}");
        return sb.toString();
    }
}

