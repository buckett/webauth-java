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
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;


/**
 * Wraps a HttpServletRequest to do some Webauth magic.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
@SuppressWarnings("deprecation")
public class RequestWrapper extends HttpServletRequestWrapper {

    
    /** The username to return from .getRemoteUser(). */
    private String username;
    /** The Principal for this user. */
    private Principal princ;
    
    /** The regexp to remove the Webauth tokens in query params. */
    private static final String WEBAUTH_REPLACE_REGEXP = "[&|\\?]?WEBAUTHR=.*$";
    
    
    /**
     * Initialise the wrapper.
     * @param   request     The request to wrap.
     */
    public RequestWrapper(HttpServletRequest request) { super(request); }


    /**
     * Initialise the wrapper.
     * @param   request     The request to wrap.
     * @param   username    The username the user has authenticated as.
     */
    public RequestWrapper(HttpServletRequest request, String username) {
        super(request);
        this.username = username;
    }
    
    
    /** Return WebAuth as auth type. */
    @Override public String getAuthType() { return "WebAuth"; }
    
    
    /** Return the username the user has authenticated as. */
    @Override public String getRemoteUser() { return username; }
    
    
    /** Return the principal. */
    @Override public synchronized Principal getUserPrincipal() {
        if(princ == null) {
            // TODO: create the principal with a real krb5 princ name, not just a username
            princ = new KerberosPrincipal(username);
        }
        return princ;
    }
    
    
    /** Hide any Webauth request parameters in the request string. */
    @Override public String getQueryString() {
        String queryString = super.getQueryString();
        if(queryString != null) {
            queryString = queryString.replaceFirst(WEBAUTH_REPLACE_REGEXP, "");
            if(!(queryString.length() > 0)) { queryString = null; }
        }
        return queryString;
    }

    
    /** Hide any Webauth request parameters in the request string. */
    @Override public String getParameter(String key) {
        if("WEBAUTHR".equals(key)) { return null; }
        String param = super.getParameter(key);
        if(param != null) { param = param.replaceFirst(WEBAUTH_REPLACE_REGEXP, ""); }
        return param;
    }
    
    
    /** Hide any Webauth request parameters in the request string. */
    @SuppressWarnings("unchecked")
    @Override public Map <String,String[]> getParameterMap() {
        Map <String,String[]> params = super.getParameterMap();
        if(params == null || params.size() == 0) { return params; }
        Map <String,String[]> modified = new HashMap <String,String[]>(params);
        modified.remove("WEBAUTHR");
        // XXX: the following should be removed once the WebKDC stops creating invalid request strings
        for(String key : modified.keySet()) {
            String[] values = modified.get(key);
            List <String> modifiedValues = new ArrayList <String>(values.length);
            for(String value : values) {
                modifiedValues.add(value.replaceFirst(WEBAUTH_REPLACE_REGEXP, ""));
            }
            modified.put(key, modifiedValues.toArray(new String[modifiedValues.size()]));
        }
        // XXX: end
        return Collections.unmodifiableMap(modified);
    }
    
    
    /** Hide any Webauth request parameters in the request string. */
    @Override public String[] getParameterValues(String key) {
        if("WEBAUTHR".equals(key)) { return null; }
        // XXX: the following should be removed once the WebKDC stops creating invalid request strings
        String[] values = super.getParameterValues(key);
        if(values == null) { return null; }
        List <String> modifiedValues = new ArrayList <String>(values.length);
        for(String value : values) {
            modifiedValues.add(value.replaceFirst(WEBAUTH_REPLACE_REGEXP, ""));
        }
        return modifiedValues.toArray(new String[modifiedValues.size()]);
        // XXX: end
        // return super.getParameterValues(key);
    }
    
    
    /** Hide any Webauth request parameters in the request string. */
    @SuppressWarnings("unchecked")
    @Override public Enumeration <String> getParameterNames() {
        Enumeration <String> orig = super.getParameterNames();
        Object value = new Object();
        Hashtable <String,Object> table = new Hashtable <String,Object>();
        while(orig.hasMoreElements()) {
            String key = orig.nextElement();
            if("WEBAUTHR".equals(key)) { continue; }
            table.put(key, value);
        }
        return table.keys();
    }
}