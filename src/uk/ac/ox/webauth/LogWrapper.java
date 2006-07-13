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
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;


/**
 * Wrap whatever type of logging we are doing this month.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class LogWrapper {
    
    
    /** A ServletContext to log to. */
    private ServletContext context;
    /** The name of this filter. */
    private String name;
    /** Should we print debugging output? */
    public boolean debug() { return debug; }
    private boolean debug;
    
    
    /** Do nothing constructor. */
    public LogWrapper() { }
    
    
    /**
     * Initialise the log wrapper with a FilterConfig.
     * @param   config  The FilterConfig to get info from.
     */
    public LogWrapper(FilterConfig config) {
        context = config.getServletContext();
        name = config.getFilterName();
        debug = Boolean.parseBoolean(config.getInitParameter("WebAuthDebug"));
    }
    
    
    /**
     * Print an error message. The message will be prepended with "ERROR: ".
     * @param   message The message to log.
     */
    public void error(String message) { context.log("ERROR: "+name+": "+message); }
    
    
    /**
     * Print an error message and stack trace. The message will be prepended
     * with "ERROR: ".
     * @param   message     The message to log.
     * @param   throwable   The Throwable to log.
     */
    public void error(String message, Throwable throwable) { context.log("ERROR: "+name+": "+message, throwable); }
    
    
    /**
     * Print a debug message. The message will be prepended with "DEBUG: ".
     * @param   message The message to log.
     */
    public void debug(String message) {
        if(!debug) { return; }
        context.log("DEBUG: "+name+": "+message);
    }

    /**
     * Print a debug message. The message will be prepended with "DEBUG: ".
     * @param   message The message to log.
     * @param   throwable   The Throwable to log.
     */
    public void debug(String message, Throwable throwable) {
        if(!debug) { return; }
        context.log("DEBUG: "+name+": "+message, throwable);
    }
}