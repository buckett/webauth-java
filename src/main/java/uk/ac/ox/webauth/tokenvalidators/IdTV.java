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
package uk.ac.ox.webauth.tokenvalidators;
import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERApplicationSpecific;
import uk.ac.ox.webauth.asn1.KrbApReq;
import uk.ac.ox.webauth.LogWrapper;
import uk.ac.ox.webauth.Token;


/**
 * Validate an id token.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class IdTV extends Validator {

    
    private SecretKey sessionKey;
    
    
    /**
     * Initialise the IdTV.
     * @param   token   The ID token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public IdTV(Token token, LogWrapper logger) { super("id", token, logger); }


    /**
     * Initialise the IdTV.
     * @param   token   The ID token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public IdTV(SecretKey sessionKey, Token token, LogWrapper logger) {
        super("id", token, logger);
        this.sessionKey = sessionKey;
    }
    

    /**
     * Check that the token is valid, it's an id token, it has not passed it's
     * expiry time, it was not created more than 5 minutes ago, and if it is a
     * webkdc response then check that the username string is longer than 0 chars.
     * @return  true if and only if this token is valid in all ways.
     */
    public boolean valid() {
        if(invalidToken() || wrongType() || expired() || olderThan(FIVE_MINUTES) || invalidSubject()) { return false; }
        
        if("webkdc".equals(token.getString("sa"))) {
            if(logger.debug()) { logger.debug("Got an sa=webkdc id token, trusting the username."); }
        }
        else if("krb5".equals(token.getString("sa"))) {
            if(logger.debug()) { logger.debug("Got an sa=krb5 id token."); }
            try {
                ASN1InputStream asn1in = new ASN1InputStream(token.getBinary("sad"));
                KrbApReq krbApReq = new KrbApReq((DERApplicationSpecific)asn1in.readObject(), 0, null);
                // TODO: should probably do some verification here???
                if(logger.debug()) { logger.debug("sad authenticator verified."); }
            }
            catch(GeneralSecurityException gse) {
                if(logger.debug()) { logger.debug("sad authenticator validation failed.", gse); }
                return false;
            }
            catch(IOException ioe) {
                logger.error("There was a problem validating the id token.", ioe);
                return false;
            }
        }
        else {
            if(logger.debug()) { logger.debug(type+" token did not have a valid 'sa' value: "+token.getString("sa")); }
            return false;
        }
        
        return true;
    }
}