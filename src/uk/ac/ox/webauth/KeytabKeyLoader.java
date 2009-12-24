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
import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.Subject;

import static javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag.REQUIRED;


/**
 * Acquire a Kerberos key from a keytab.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author      Mats Henrikson
 * @version     $LastChangedRevision$
 */
public class KeytabKeyLoader {

    
    /** The principal whose key to acquire. */
    private String principal;
    /** The keytab in which to look for the principal's key. */
    private File keytab;
    /** Refresh keytab every time. */
    private boolean keytabRefresh;


    /**
     * Simple test method that tries to acquire a type 16 key from a given keytab.
     * @param   args    First principal and then the keytab to load a key from.
     * @throws  Exception   when something goes wrong.
     */
    public static void main(String[] args) throws Exception {
        KeytabKeyLoader kkl = new KeytabKeyLoader(args[0], args[1], false);
        Subject sub = kkl.acquire();
        System.out.println(sub.toString());
        for(KerberosKey k : sub.getPrivateCredentials(KerberosKey.class)) {
            // only grab a "Triple DES cbc mode with HMAC/sha1" type key
            if(k.getKeyType() == 16) {
                System.out.println("Aquired the key from the keytab.");
                System.out.println(k);
                return;
            }
        }
        System.err.println("Could not acquire the key from the keytab.");
        System.exit(1);
    }
    
    
    /**
     * Initialise the prototype with the keytab filename and the
     * principal to grab a key for.
     * @param   princ         The principal to grab a key for.
     * @param   ktb           The filename of the keytab to load the key from.
     * @param   keytabRefresh Whether to refresh the keytab before login.
     */
    public KeytabKeyLoader(String princ, String ktb, boolean keytabRefresh) {
         this.principal = princ;
         this.keytab = new File(ktb);
         this.keytabRefresh = keytabRefresh;
    }
    
    
    /**
     * Tries to acquire the keys from the keytab.
     * @return  Returns a Subject with all the credentials acquired.
     * @throws  LoginException  If there is a problem acquiring the key.
     * @throws  IOException     If there is a problem reading the keytab.
     */
    public Subject acquire() throws LoginException, IOException {
        if(!keytab.exists()) { throw new IOException("The keytab '"+keytab.getPath()+"' does not exist."); }
        if(!keytab.isFile()) { throw new IOException("The keytab '"+keytab.getPath()+"' is not a regular file."); }
        if(!keytab.canRead()) { throw new IOException("The keytab '"+keytab.getPath()+"' is not readable."); }
        
        LoginContext lc = null;
        lc = new LoginContext("__Webauth-Keytab__", null, null, new StaticConfiguration(principal, keytab, keytabRefresh));
        lc.login();
        return lc.getSubject();
    }



    /** Implements a different Configuration so we don't have to read a file. */
    private static class StaticConfiguration extends Configuration {
        
        /** The options for this Configuration. */
        private Map <String,String> config;
        
        /**
         * Configure the options map.
         * @param   princ         The principal to load a key for.
         * @param   keytab        The keytab file to use.
         * @param   refreshKeytab Whether to refresh the keytab prior to login
         */
        public StaticConfiguration(String princ, File keytab, boolean refreshKeytab) {
            Map <String,String> c = new HashMap <String,String> ();
            c.put("keyTab", keytab.getPath());
            c.put("principal", princ);
            // TODO: configure debug somewhere externally?
            c.put("debug", "false");
            c.put("useKeyTab", "true");
            c.put("storeKey", "true");
            c.put("doNotPrompt", "true");
            c.put("refreshKrb5Config", Boolean.valueOf(refreshKeytab).toString());
            config = Collections.unmodifiableMap(c);
        }
        
        /**
         * Return the AppConfigurationEntry for the Keytab-Test login system.
         * @param   name    The string "Keytab-Test" must be passed here to get
         *                  anything back.
         */
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            if("__Webauth-Keytab__".equals(name)) {
                AppConfigurationEntry[] e = new AppConfigurationEntry[1];
                e[0] = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule", REQUIRED, config);
                return e;
            }
            return null;
        }
        
        /** Stub to satisfy the extends. */
        public void refresh() {}
    }
}