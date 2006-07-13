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
 * Validate an app token.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class AppTV extends Validator {

    
    /**
     * Initialise the AppTV.
     * @param   token   The ID token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public AppTV(Token token, LogWrapper logger) { super("app", token, logger); }
    

    /**
     * Check that the token is valid, it's an app token, and it has not passed
     * it's expiry time.
     * @return  true if and only if this token is valid in all ways.
     */
    public boolean valid() {
        if(invalidToken() || wrongType() || expired()) { return false; }
        if(logger.debug()) { logger.debug("Got a valid app token."); }
        return true;
    }
}