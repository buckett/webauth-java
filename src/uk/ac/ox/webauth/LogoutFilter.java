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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


/**
 * Filter to logout a WebAuth authenticted user.
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author      buckett
 * @version     $LastChangedRevision$
 */
public class LogoutFilter implements Filter {

    
    private LogWrapper logger;

    
    public void destroy() { }

    
    /**
     * Attempt to log the user out of thier WebAuth session with the current
     * site. This is done by removing the cookies.
     */
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (!(request instanceof HttpServletRequest) || !(response instanceof HttpServletResponse))
            throw new ServletException("Filter only works with HTTP.");
        
        HttpServletRequest httpRequest = (HttpServletRequest)request;
        HttpServletResponse httpResponse = (HttpServletResponse)response;
        
        if (httpRequest.getRemoteUser() == null ||  !"WebAuth".equals(httpRequest.getAuthType())) {
            logger.debug("No WebAuth credentials found. Are filters in the correct order?");
        }
        
        boolean foundCookies = false;
        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().startsWith("webauth")) {
                    cookie.setMaxAge(0);
                    cookie.setValue("");
                    cookie.setSecure(true);
                    cookie.setPath("/");
                    httpResponse.addCookie(cookie);
                    foundCookies = true;
                }
            }
        }
        if (!foundCookies) {
            logger.error("WebAuth Logout Failed. No cookies found.");
        }
        else {
            logger.debug("WebAuth Logout Ok.");
        }
        
        chain.doFilter(httpRequest, httpResponse);
    }

    
    public void init(FilterConfig config) throws ServletException {
        logger = new LogWrapper(config);
    }

}
