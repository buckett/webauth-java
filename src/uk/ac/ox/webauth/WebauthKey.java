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
package uk.ac.ox.webauth;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;


/**
 * A Webauth key.
 *
 * <p><b>Note: this class has a natural ordering that is inconsistent with equals.</b>
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class WebauthKey implements Comparable<WebauthKey> {
    
    
    /** Valid after unix timestamp, seconds since the epoch. */
    public int va() { return va; }
    private int va;
    /** Created time unix timestamp, seconds since the epoch. */
    public int ct() { return ct; }
    private int ct;
    /** Key type. 1: AES. */
    public int kt() { return kt; }
    private int kt;
    /** Key number in the keyring file. */
    public int kn() { return kn; }
    private int kn;
    /** Base64 encoded key data. */
    public String kd() { return kd; }
    private String kd;
    /** The SecretKey built from the data. */
    public SecretKey key() { return key; }
    private SecretKey key;
    
    
    /** Initialise the key and Base64 decode the key data. */
    public WebauthKey(int kn, int ct, int va, int kt, String kd) throws ServletException {
        this.kn = kn;
        this.ct = ct;
        this.va = va;
        this.kt = kt;
        this.kd = kd;
        try { this.key = new SecretKeySpec(Hex.decodeHex(kd.toCharArray()), "AES"); }
        catch(DecoderException de) { throw new ServletException(de); }
    }
    
    
    /** Return a string suitable for writing to a keyring. */
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("ct").append(kn).append("=").append(ct);
        sb.append(";va").append(kn).append("=").append(va);
        sb.append(";kt").append(kn).append("=").append(kt);
        sb.append(";kd").append(kn).append("=").append(kd).append(";");
        return sb.toString();
    }
    
    
    /** Sorts according to valid-after value. */
    public int compareTo(WebauthKey key) throws ClassCastException { return va - key.va(); }
}