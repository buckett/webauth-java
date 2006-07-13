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
import java.util.concurrent.ConcurrentHashMap;
import java.util.Date;
import java.util.List;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.UnavailableException;

import static uk.ac.ox.webauth.tokenvalidators.Validator.FIVE_MINUTES;


/**
 * Servlet Filter that Webauth authenticates a person.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class Filter implements javax.servlet.Filter {
    
    
    /** The config to use for this filter. */
    private FilterConfig config;
    /** Log to this. */
    private LogWrapper logger;

    /** The private WAS AES key manager. */
    private static PrivateKeyManager privateKeyManager;
    /** The service token for the WebKDC. */
    private static WebKDCServiceToken serviceToken;
    /** A Map to temporary hold all the data needed for JAAS. */
    private static Map <Thread,JAASData> jaas = new ConcurrentHashMap <Thread,JAASData>();
    
    
    public void init(FilterConfig filterConfig) throws ServletException {
        config = new FilterConfigWrapper(filterConfig);
        logger = new LogWrapper(config);
        privateKeyManager();
        serviceToken();
    }


    public void destroy() { }
    
    
    /**
     * Checks if the user is allowed through, and redirects to the WebKDC if
     * they are not.
     * @throws  ServletException
     */
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
            throws IOException, ServletException {
        
        if(!(servletRequest instanceof HttpServletRequest) || !(servletResponse instanceof HttpServletResponse)) {
            throw new ServletException("The Servlet{Request,Response} are not HttpServlet{Request,Response}.");
        }
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        if(!request.isSecure()) { throw new ServletException("This request was not SSL/TLS protected."); }
        if(!serviceToken.valid()) { throw new UnavailableException("The WebKDC service token is invalid."); }
        
        FilterWorker worker = new FilterWorker(request, response, chain, config, logger, privateKeyManager, jaas,
                serviceToken.tokenData(), serviceToken.sessionKey());

        // TODO: add error handling???
        worker.run();
    }


    /**
     * Return the JAAS data for the LoginModule.
     * @param   thread  The thread key.
     * @return  The JAAS data.
     */
    /*package-private*/ static JAASData jaas(Thread thread) { return jaas.get(thread); }
    
    
    /**
     * Initialises a private key manager for the WAS session keys.
     * @throws  ServletException    if there was a problem loading the keyring.
     */
    private synchronized void privateKeyManager() throws ServletException {
        if(privateKeyManager != null) { return; }
        privateKeyManager = new PrivateKeyManager(config.getInitParameter("WebAuthKeyring"),
                Boolean.parseBoolean(config.getInitParameter("AutoAddKeys")),
                Boolean.parseBoolean(config.getInitParameter("AutoRemoveKeys")),
                logger);
    }
    
    
    /** Check if we have a service token yet, and if not acquire one. */
    private synchronized void serviceToken() throws ServletException {
        if(serviceToken != null) { return; }
        serviceToken = new WebKDCServiceToken(config, logger);
        serviceToken.refresh();
        Thread t = new Thread("WebKDC Service Token Refresher Thread") {
            public void run() {
                logger.debug("Started a new Service Token Refresher Thread.");
                while(true) {
                    long sleepTime = serviceToken.sleepTime();
                    if(sleepTime > 0) {
                        logger.debug("Sleeping until "+new Date(System.currentTimeMillis()+sleepTime)+" ("+sleepTime
                                +" milliseconds) before refreshing the WebKDC service token.");
                        try { Thread.sleep(sleepTime); }
                        catch(InterruptedException ie) {
                            logger.error("The WebKDC Service Token Refresher Thread was interrupted while sleeping, "
                                    +"this shouldn't happen.", ie);
                        }
                    }
                    try { serviceToken.refresh(); }
                    catch(ServletException se) { logger.error(se.getMessage(), se); }
                }
            }
        };
        t.setDaemon(true);
        t.start();
    }
    
    
    
    /** A very simple container for JAAS data. */
    /*package-private*/ static class JAASData {
        /*package-private*/ String username;
        /*package-private*/ List <Token> tickets;
        /*package-private*/ JAASData(String username, List <Token> tickets) {
            this.username = username;
            this.tickets = tickets;
        }
    }
}