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
 * Validate a proxy token.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class ProxyTV extends Validator {

    
    /**
     * Initialise the ProxyTV.
     * @param   token   The proxy token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public ProxyTV(Token token, LogWrapper logger) { super("proxy", token, logger); }
    

    /**
     * Check that the token is valid, it's a proxy token, it has not passed it's
     * expiry time, the username string is longer than 0 chars, it is a krb5
     * token, and the proxy token is longer than 0 bytes.
     * @return  true if and only if this token is valid in all ways.
     */
    public boolean valid() {
        if(invalidToken() || wrongType() || expired() || olderThan(FIVE_MINUTES) || invalidSubject()) { return false; }
        
        if(!"krb5".equals(token.getString("pt"))) {
            if(logger.debug()) { logger.debug(type+" token had incorrect 'pt' value: "+token.getString("pt")); }
            return false;
        }
        
        byte[] wt = token.getBinary("wt");
        if(wt == null || wt.length < 1) {
            if(logger.debug()) { logger.debug(type+" token did not have a valid 'wt' value."); }
            return false;
        }
        
        return true;
    }
}