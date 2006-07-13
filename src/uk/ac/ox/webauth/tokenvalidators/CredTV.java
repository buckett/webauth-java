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
import uk.ac.ox.webauth.LogWrapper;
import uk.ac.ox.webauth.Token;


/**
 * Validate a Cred token.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class CredTV extends Validator {

    
    /**
     * Initialise the CredTV.
     * @param   token   The cred token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public CredTV(Token token, LogWrapper logger) { super("cred", token, logger); }
    

    /**
     * Check that the token is valid, it's a cred token, it has not passed it's
     * expiry time, the username string is longer than 0 chars, it is a krb5
     * token, the cred token data is longer than 0 bytes, and the crs and crd
     * exists and is longer than 0 chars.
     * @return  true if and only if this token is valid in all ways.
     */
    public boolean valid() {
        if(invalidToken() || wrongType() || expired() || invalidSubject()) { return false; }
        
        String crs = token.getString("crs");
        if(crs == null || crs.length() < 1) {
            if(logger.debug()) { logger.debug(type+" token did not have a valid 'crs' value."); }
            return false;
        }
        
        String crt = token.getString("crt");
        if(crt == null || crt.length() < 1) {
            if(logger.debug()) { logger.debug(type+" token did not have a valid 'crt' value."); }
            return false;
        }
        
        byte[] crd = token.getBinary("crd");
        if(crd == null || crd.length < 1) {
            if(logger.debug()) { logger.debug(type+" token did not have a valid 'crd' value."); }
            return false;
        }
        
        return true;
    }
}