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
import java.util.Date;
import uk.ac.ox.webauth.LogWrapper;
import uk.ac.ox.webauth.Token;


/**
 * Base for the token validators.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public abstract class Validator {

    // TODO: this class, how it is used, and it's subclasses are in a bit of a mess and could be improved...
 
    /** The type this token is, used for log messages. */
    /*package-private*/ String type;
    /** The token to be validated. */
    /*package-private*/ Token token;
    /** Where to log messages. */
    /*package-private*/ LogWrapper logger;
    
    /** 5 minutes in milliseconds. */
    public static final long FIVE_MINUTES = 300000;
    
    
    /**
     * Initialise the TokenValidator.
     * @param   type    The type of token.
     * @param   token   The token to validate.
     * @param   logger  A LogWrapper to log to.
     */
    public Validator(String type, Token token, LogWrapper logger) {
        this.type = type;
        this.token = token;
        this.logger = logger;
    }
    
    
    /**
     * Each class must implement this to do whatever validation it requires.
     * @return  true if this token is valid in all ways, false otherwise.
     */
    public abstract boolean valid();
    
    
    /**
     * Check if the token itself is invalid.
     * @return  true if and only if the token is invalid.
     */
    public boolean invalidToken() {
        boolean invalid = token == null || !token.valid();
        if(invalid && logger.debug()) { logger.debug(type+" token is not valid."); }
        return invalid;
    }
    
    
    /**
     * Check if the token is of the wrong type.
     * @return  true if and only if the token is of the wrong type, i.e. if
     *          the type that the base Validator class was initialised with does
     *          not equal the token "t" value.
     */
    public boolean wrongType() {
        boolean wrong = !type.equals(token.getString("t"));
        if(wrong && logger.debug()) {
            logger.debug(type+" token did not have correct type value: "+token.getString("t"));
        }
        return wrong;
    }
    
    
    /**
     * Check if the token has passed it's expiration time.
     * @return  true if and only if the token has passed the time stored in the
     *          "et" token.
     */
    public boolean expired() {
        boolean expired = false;
        byte[] date = token.getBinary("et");
        if(date != null) {
            expired = new Date().compareTo(Token.bytesToDate(date)) > 0;
            if(expired && logger.debug()) {
                logger.debug(type+" token expired at "+Token.bytesToDate(date));
            }
        }
        return expired;
    }
    
    
    /**
     * Check if the token is older than the time period given.
     * @return  true if and only if the token is older than the time period
     *          given in milliseconds.
     */
    public boolean olderThan(long milliseconds) {
        boolean older = olderThan(token, milliseconds);
        if(older && logger.debug()) {
            logger.debug(type+" token was created more than "+milliseconds+" milliseconds ago ("
                    +Token.bytesToDate(token.getBinary("ct"))+").");
        }
        return older;
    }
    
    
    /**
     * Check if the token is older than the time period given.
     * @return  true if and only if the token is older than the time period
     *          given in milliseconds.
     */
    public static boolean olderThan(Token t, long milliseconds) {
        return Token.bytesToInt(t.getBinary("ct"))*1000L+milliseconds < System.currentTimeMillis();
    }


    /**
     * Check if the subject string is invalid.
     * @return  true if and only if the subject string is invalid.
     */
    public boolean invalidSubject() {
        String subject = token.getString("s");
        boolean invalid = subject == null || subject.length() < 1;
        if(invalid && logger.debug()) { logger.debug("Got a "+type+" token without a valid subject: "+subject); }
        return invalid;
    }
    
    
    /** Check if the given token is a proxy token. */
    public static boolean isProxyToken(Token t) { return "proxy".equals(t.getString("t")); }
    
    
    /**
     * Validate a token.
     * @param   type    The token type, its 't' value.
     * @param   t       The token to validate.
     * @return  Returns true if and only if the token is valid.
     */
    public static boolean validate(String type, Token t, LogWrapper logger) throws IllegalArgumentException {
        Validator v = null;
        if("app".equals(type)) { v = new AppTV(t, logger); }
        else if("id".equals(type)) { v = new IdTV(t, logger); }
        else if("proxy".equals(type)) { v = new ProxyTV(t, logger); }
        else if("cred".equals(type)) { v = new CredTV(t, logger); }
        else { throw new IllegalArgumentException("Invalid type '"+type+"', no such token validator."); }
        boolean valid = v.valid();
        if(logger.debug()) { logger.debug("Validated '"+type+"' type token with result: "+valid+"."); }
        return valid;
    }
}