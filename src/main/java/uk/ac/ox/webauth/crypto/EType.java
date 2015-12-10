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
import java.io.IOException;
import java.security.GeneralSecurityException;
import org.bouncycastle.asn1.ASN1Encodable;


/**
 * Simple interface for different krb5 crypto types to implement.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public abstract class EType {
    
    
    /** Decrypt the cipher and return an ASN.1 object. */
    public abstract ASN1Encodable decrypt(byte[] data) throws IOException, GeneralSecurityException;


    /** Encrypt the ASN1Encodable and return an array of bytes. */
    public abstract byte[] encrypt(ASN1Encodable o) throws IOException, GeneralSecurityException;


    public static String stringOfBits(byte oneByte) {
        StringBuilder sb = new StringBuilder();
        int[] singles = {128,64,32,16,8,4,2,1};
        for(int single : singles) {
            if((oneByte&single) > 0) { sb.append("1"); }
            else { sb.append("0"); }
        }
        return sb.toString();
    }
}