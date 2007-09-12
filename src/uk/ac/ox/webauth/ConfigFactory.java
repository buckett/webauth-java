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

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

/**
 * Returns a FilterConfig class for configuring the filter.
 * If ConfigClass is set then the factory tries to create an instance of that 
 * class and uses it for all the configuration. Otherwise it looks for ConfigFile
 * and then attempts to load the properties from that file.
 * <p>
 * This factory was added so that it is easier to integrate with other systems.
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Matthew Buckett
 * @version    $LastChangedRevision$
 */
public class ConfigFactory
{
    public static FilterConfig getConfig (FilterConfig config) throws ServletException
    {
        FilterConfig newConfig = config;

        ServletContext context = newConfig.getServletContext();
       
        String confClass = config.getInitParameter("ConfigClass");
        if (confClass != null) {
            try
            {
                newConfig  = (FilterConfig)Class.forName(confClass).newInstance();
            }
            catch (ClassNotFoundException e)
            {
                context.log("ConfigClass parameter, class not found ("+ confClass+")", e);
            }
            catch (InstantiationException e)
            {
                context.log("ConfigClass parameter, failed to create ("+ confClass+")", e);
            }
            catch (IllegalAccessException e)
            {
                context.log("ConfigClass parameter, illegal access ("+ confClass+")", e);
            }
            catch (ClassCastException e)
            {
                context.log("ConfigClass parameter, doesn't implement FilterConfig ("+ confClass+")", e);
            }
        } else {
            String confFile = config.getInitParameter("ConfigFile");

            if (confFile != null) {
                newConfig = new FilterConfigWrapper(config, confFile); 
            }
        }
        
        boolean debug = Boolean.parseBoolean(config.getInitParameter("WebAuthDebug"));
        if(debug) {
            String prefix = "DEBUG: "+newConfig.getFilterName()+": ";
            context.log(prefix+"Filter newConfiguration options:");
            for(Enumeration names = newConfig.getInitParameterNames(); names.hasMoreElements();) {
                String key = (String)names.nextElement();
                context.log(prefix+"    "+key+": "+newConfig.getInitParameter(key));
            }
        }
        
        return newConfig;
    }

}
