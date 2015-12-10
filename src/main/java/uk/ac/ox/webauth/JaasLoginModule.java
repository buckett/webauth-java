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
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import javax.security.auth.Subject;

import static javax.security.auth.kerberos.KerberosPrincipal.KRB_NT_PRINCIPAL;
import static javax.security.auth.kerberos.KerberosPrincipal.KRB_NT_SRV_HST;


/**
 * A Webauth JAAS LoginModule. This LoginModule does not take a CallbackHandler,
 * but depends on the WebauthFilter.doFilter() method to have run in the same
 * thread as our login() method, and that the WebauthFilter instance was loaded
 * by the same class loader in order for static fields to point to the correct
 * instances.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class JaasLoginModule implements LoginModule {
    
    
    /** The Subject, if any, provided by the caller. */
    private Subject subject;
    /** The KerberosPrincipal to remove from the subject on logout. */
    private Principal krb5princ;
    /** The tickets to remove from the subject on logout. */
    private List <KerberosTicket> krb5ticks = new ArrayList <KerberosTicket>();
    /** Should we print debugging info? */
    //private boolean debug;
    /** Some booleans to hold state. */
    private boolean login;
    /** The Filter.JAASData, if we can get it. */
    private Filter.JAASData jaasData;
    
    
    public void initialize(Subject subject, CallbackHandler CallbackHandler, Map <String,?> sharedState,
            Map <String,?> options) {
        this.subject = subject;
        //debug = Boolean.parseBoolean((String)options.get("debug"));
    }
    
    
    public boolean login() throws LoginException {
        jaasData = Filter.jaas(Thread.currentThread());
        if(jaasData == null) {
            login = false;
            throw new LoginException("JAAS Webauth login failed This could be caused by "
                    +"(among other things) the location not being Webauth Java protected, the Webauth Java library "
                    +"being loaded in the wrong classloader, or the webapp container not using the same thread to "
                    +"process the entire Filter chain and JAAS login.");
        }
        else { login = true; }
        return true;
    }
    
    
    public boolean commit() throws LoginException {
        if(login == false) { return false; }
        
        // add the krb5 principal
        // TODO: create the principal with a real krb5 princ name, not just a username
        krb5princ = new KerberosPrincipal(jaasData.username);
        subject.getPrincipals().add(krb5princ);
        
        for(Token t : jaasData.tickets) {
            // create the boolean array and set the flags from the int value
            boolean[] flags = new boolean[32];
            Integer intFlags = Token.bytesToInt(t.getBinary("f"));
            for(int i = 0; i < flags.length; i++) {
                if(Integer.highestOneBit(intFlags) > 0) { flags[i] = true; }
                else { flags[i] = false; }
                intFlags = Integer.rotateLeft(intFlags, 1);
            }
            
            // need to create the fake krbtgt ticket (if any) with a principal type, otherwise the name changes to lc
            int serviceType = t.getString("s").startsWith("krbtgt/") ? KRB_NT_PRINCIPAL : KRB_NT_SRV_HST;
            
            // create and add the ticket
            KerberosTicket ticket = new KerberosTicket(
                    t.getBinary("t"),
                    new KerberosPrincipal(t.getString("c")),
                    new KerberosPrincipal(t.getString("s"), serviceType),
                    t.getBinary("k"),
                    Token.bytesToInt(t.getBinary("K")),
                    flags,
                    Token.bytesToDate(t.getBinary("ta")),
                    Token.bytesToDate(t.getBinary("ts")),
                    Token.bytesToDate(t.getBinary("te")),
                    Token.bytesToDate(t.getBinary("tr")),
                    null);
            krb5ticks.add(ticket);
        }
        subject.getPrivateCredentials().addAll(krb5ticks);
        
        return true;
    }
    
    
    public boolean abort() throws LoginException {
        jaasData = null;
        return login;
    }
    
    
    public boolean logout() throws LoginException {
        // if the subject is read only then we can't remove the principal so throw an exception
        if(subject.isReadOnly()) {
            throw new LoginException("Cannot remove Kerberos principal from subject as the Subject has been marked "
                    +"read-only.");
        }
        subject.getPrincipals().remove(krb5princ);
        subject.getPrivateCredentials().removeAll(krb5ticks);
        return true;
    }
}