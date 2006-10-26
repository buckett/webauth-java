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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidatorException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.Subject;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import uk.ac.ox.webauth.asn1.KrbApReq;


/**
 * Encapsulates a WebKDC service token and logic to manage it.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class WebKDCServiceToken {

    
    /** The number of milliseconds to wait before retrying a refresh after a faliure. */
    private static final long WAIT = 600000;            // 10 minutes
    /** The number of milliseconds before a service token expires to try to refresh it. */
    private static final long REFRESH_TIME = 1800000;   // 30 minutes

    /** The keytab to load the service principal key from. */
    private String webAuthKeytab;
    /** The principal for whom to load the key from the keytab for. */
    private String webAuthServicePrincipal;
    /** The WebKDC principal to make requests to. */
    private String webAuthWebKdcPrincipal;
    /** The WebKDC request URL to post XML requests to. */
    private String webAuthWebKdcURL;
    /** The ServletContext to log to. */
    private LogWrapper logger;

    /** The tokenData string. */
    public String tokenData() { return tokenData; }
    private String tokenData;
    /** The sessionKey. */
    public SecretKey sessionKey() { return sessionKey; }
    private SecretKey sessionKey;
    /** The time the session key expires in seconds since the epoch. */
    public int expires() { return expires; }
    private int expires;
    /** Is this a valid token, did the last refresh succeed? */
    public boolean valid() { return valid; }
    private boolean valid = false;
    
    
    /**
     * Construct the token with necessary info on how to refresh itself.
     * @param   config  The FilterConfig to grab settings from.
     * @param   logger  The LogWrapper to log to.
     */
    public WebKDCServiceToken(FilterConfig config, LogWrapper logger) {
        this.logger = logger;
        this.webAuthServicePrincipal = config.getInitParameter("WebAuthServicePrincipal");
        this.webAuthKeytab = config.getInitParameter("WebAuthKeytab");
        this.webAuthWebKdcPrincipal = config.getInitParameter("WebAuthWebKdcPrincipal");
        this.webAuthWebKdcURL = config.getInitParameter("WebAuthWebKdcURL");
    }
    
    
    /** Refresh or acquire a new WebKDC service token. */
    public synchronized void refresh() throws ServletException {
        valid = false;
        try {
            // load the service key from the keytab
            KeytabKeyLoader kkl = new KeytabKeyLoader(webAuthServicePrincipal, webAuthKeytab);
            Subject sub = kkl.acquire();
            
            // get a service ticket
            try { Subject.doAs(sub, new ServiceTicketGrabberHack(webAuthServicePrincipal, webAuthWebKdcPrincipal)); }
            catch(Exception e) { e.printStackTrace(); }
            KerberosTicket ticket = null;
            for(KerberosTicket t : sub.getPrivateCredentials(KerberosTicket.class)) {
                if(t.getServer().getName().startsWith(webAuthWebKdcPrincipal)) {
                    ticket = t;
                }
            }
            
            // request a webkdc token
            KrbApReq k = new KrbApReq(ticket);
            logger.debug("Sending the following KrbApReq:\n"+k.toString());
            byte[] krb_ap_req = k.toASN1Object().getEncoded();
            WebauthGetTokensRequest wgtr = new WebauthGetTokensRequest(webAuthWebKdcURL, krb_ap_req);
            wgtr.tokenRequest();
            tokenData = wgtr.tokenData();
            sessionKey = new SecretKeySpec(FilterWorker.base64decode(wgtr.sessionKey()), "AES");
            try { expires = Integer.parseInt(wgtr.expires()); }
            catch(NumberFormatException nfe) {
                logger.error(null, nfe);
                expires = 0;
                return;
            }
            valid = true;
            if(logger.debug()) {
                logger.debug("Refreshed WebKDC service token "+webAuthWebKdcPrincipal+" for principal "
                        +webAuthServicePrincipal+".");
            }
        }
        catch(IOException ioe) {
            for( Throwable cause = ioe.getCause(); cause != null; cause = cause.getCause() ) {
                if (cause instanceof CertPathValidatorException) {
                    throw new ServletException("Missing Certificate: "+cause.getMessage(), ioe);
                }
            }
            throw new ServletException("Could not refresh the WebKDC service token: "+ioe.getMessage(), ioe);
        }
        catch(GeneralSecurityException gse) {
            throw new ServletException("Could not refresh the WebKDC service token: "+gse.getMessage(), gse);
        }
    }
    
    
    /**
     * Returns the number of milliseconds to sleep before refreshing the token.
     * @return  The number of milliseconds to wait.
     */
    public synchronized long sleepTime() {
        if(!valid || expires == 0) { return WAIT; }
        return (expires*1000L)-(System.currentTimeMillis()+REFRESH_TIME);
    }
}