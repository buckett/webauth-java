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
import java.security.PrivilegedExceptionAction;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

import static org.ietf.jgss.GSSCredential.INITIATE_ONLY;
import static org.ietf.jgss.GSSName.NT_USER_NAME;


/**
 * This is a hack to grab a service ticket for the WAS to the WebKDC. If anybody
 * knows a better way of doing this then please let me know!
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class ServiceTicketGrabberHack implements PrivilegedExceptionAction {
    
    
    private String user;
    private String service;
    
    
    public ServiceTicketGrabberHack(String user, String service) {
        this.user = user;
        this.service = service;
    }
    
    
    /** This is supposed to put the service ticket in the Subject. It returns nothing. */
    public Object run() throws GSSException {
        GSSManager manager = GSSManager.getInstance();
        Oid krb5Mechanism = new Oid("1.2.840.113554.1.2.2");
        Oid krb5PrincipalNameType = new Oid("1.2.840.113554.1.2.2.1");
        // Identify who the client wishes to be
        GSSName userName = manager.createName(user, NT_USER_NAME);
        // Identify the name of the server. This uses a Kerberos-specific name format.
        GSSName serverName = manager.createName(service,  krb5PrincipalNameType);
        // Acquire credentials for the user
        GSSCredential userCreds = manager.createCredential(userName, GSSCredential.DEFAULT_LIFETIME, krb5Mechanism,
                INITIATE_ONLY);
        // Instantiate and initialize a security context that will be established with the server
        GSSContext context = manager.createContext(serverName, krb5Mechanism, userCreds, GSSContext.DEFAULT_LIFETIME);
        // this grabs the necessary service ticket!!!
        context.initSecContext(new byte[0], 0, 0);
        return null;
    }
}
