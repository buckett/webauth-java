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
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;


/**
 * A wrapper for the FilterConfig to allow loading of common options from
 * properties file. The options in the properties file can then be overridden
 * with the init parameters set in the deployment descriptor. To specify a
 * properties file to load pass the init parameter ConfigFile with
 * the path of the properties file to load to the Webauth Filter.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class FilterConfigWrapper implements FilterConfig {
    
    
    /** The FilterConfig to get all the runtime config options from. */
    private FilterConfig config;
    /** A Map holding all the final options in. */
    private Map <String,String> options = new HashMap <String,String>();
    
    
    /**
     * Initialise the config.
     * @param   config  The FilterConfig to 'wrap'.
     */
    public FilterConfigWrapper(FilterConfig config, String file) throws ServletException {
        this.config = config;

        Properties props = new Properties();
        try { props.load(new BufferedInputStream(new FileInputStream(file))); }
        catch(IOException ioe) {
            throw new ServletException("There was a problem reading the Webauth configuration file '"
                +file+"'.", ioe);
        }
        
        for(Enumeration keys = props.propertyNames(); keys.hasMoreElements();) {
            String key = (String)keys.nextElement();
            options.put(key, (String)props.getProperty(key));
        }
        
        for(Enumeration keys = props.propertyNames();keys.hasMoreElements();) {
            String key = (String)keys.nextElement();
            options.put(key, config.getInitParameter(key));
        }
    }
    
    
    public String getInitParameter(String name) { return options.get(name); }
    
    
    public Enumeration getInitParameterNames() { return Collections.enumeration(options.keySet()); }
    
    
    public String getFilterName() { return config.getFilterName(); }
    
    
    public ServletContext getServletContext() { return config.getServletContext(); }
}