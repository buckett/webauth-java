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
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import javax.servlet.ServletException;
import org.apache.commons.codec.binary.Hex;


/**
 * Key manager for the WAS private session keys. It can more or less safely
 * share it concurrently with mod_webauth.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class PrivateKeyManager {
    
    /** Where to log to. */
    private final LogWrapper logger;
    /** The keyring. */
    private File keyring;
    /** The time the keyring was last modified. */
    private long lastModified;
    /** When did we last check the keyring for changes. */
    private long lastChecked;
    /** Timestamp when we last checked if a key should be removed or added. */
    private long updateChecked;
    /** A SortedMap holding all the keys, sorted by valid-after time. */
    private List <WebauthKey> keys;
    /** The v key of the keyring. Not sure what it does but it might come in useful. */
    private int v;
    /** Should we create new keys when the old ones become too old? */
    private boolean createKeys;
    /** Should we delete keys from the keyring when they become too old? */
    private boolean removeKeys;
    
    /** Minimum interval in milliseconds between checking the keyring for updates by another process. */
    private static final long KEYRING_UPDATE_CHECK_INTERVAL = 2000;     // 2 seconds
    /** Minimum interval in milliseconds between checking if a the keyring should be updated by this manager. */
    private static final long KEYRING_UPDATE_INTERVAL = 60000;      // 1 minute
    /** How old the va value of the freshest key must be before a new key is created, in seconds. */
    private static final int KEY_NEW_AGE = 2592000;     // 30 days
    /** How old the va value of a key must be before it is removed from the keyring, in seconds. */
    private static final int KEY_REMOVE_AGE = 7776000;  // 90 days
    /** Randomiser to create keys with. */
    private static final SecureRandom RAND = new SecureRandom();
    
    
    /** Prints out a keyring given in args[0]. */
    public static void main(String[] args) throws ServletException {
        PrivateKeyManager pkm = new PrivateKeyManager(args[0], false, false, new LogWrapper());
        System.out.println(pkm.toString());
    }
    
    
    /**
     * Initialise the key manager.
     * @param   keyring         The location of the Webauth keyring.
     * @param   createKeys      Should the manager create new keys?
     * @param   removeKeys      Should the manager remove old keys?
     * @throws  ServletException    if it wasn't possible to load the keyring.
     */
    public PrivateKeyManager(String keyring, boolean createKeys, boolean removeKeys, LogWrapper logger)
            throws ServletException {
        this.logger = logger;
        this.keyring = new File(keyring);
        this.createKeys = createKeys;
        this.removeKeys = removeKeys;
        try { loadAndParse(this.keyring); }
        catch(IOException ioe) { throw new ServletException(ioe); }
        if(createKeys && !this.keyring.canWrite()) {
            throw new ServletException("Cannot write to keyring file '"+this.keyring.getPath()+"'.");
        }
    }
    
    
    /**
     * Return a list of keys that may be suitable to decode the token, most
     * suitable first.
     * @param   keyHint The token key hint.
     * @return  A List of suitable keys, most suitable first. An empty list if
     *          there are no suitable keys.
     * @throws  ServletException    if there is a problem checking the keyring.
     */
    public List <WebauthKey> suitableKeys(int keyHint) throws ServletException {
        long now = System.currentTimeMillis();
        
        // check if it's time to check the keyring for changes again
        if(lastChecked+KEYRING_UPDATE_CHECK_INTERVAL < now) {
            lastChecked = now;
            long mt = keyring.lastModified();
            if(lastModified == mt) {
                if(logger.debug()) {
                    logger.debug("Keyring "+keyring.getPath()+" appears not to have been modified, not reloading it.");
                }
            }
            else {
                lastModified = mt;
                try { loadAndParse(keyring); }
                catch(IOException ioe) { throw new ServletException(ioe); }
            }
        }
        else {
            if(logger.debug()) {
                logger.debug("Not checking keyring "+keyring.getPath()+", last checked "+new Date(lastChecked)+".");
            }
        }
        
        // check if a key should be removed or added
        if(updateChecked+KEYRING_UPDATE_INTERVAL < now) {
            updateChecked = now;
            synchronized(keys) {
                boolean modified = false;
                if(createKeys) {
                    if(keys.size() < 1 || (keys.get(0).va()+KEY_NEW_AGE)*1000L < now) {
                        byte[] keyData = new byte[16];
                        RAND.nextBytes(keyData);
                        int timestamp = (int)(now/1000);
                        keys.add(0, new WebauthKey(keys.size(), timestamp, timestamp, 1,
                                new String(Hex.encodeHex(keyData))));
                        modified = true;
                        if(logger.debug()) {
                            logger.debug("Added a new key to keyring: "+keyring.getPath()+",\n"+this.toString());
                        }
                    }
                    
                }
                if(removeKeys) {
                    for(Iterator <WebauthKey> i = keys.iterator(); i.hasNext();) {
                        WebauthKey key = i.next();
                        if((key.va()+KEY_REMOVE_AGE)*1000L < now) {
                            i.remove();
                            modified = true;
                            if(logger.debug()) {
                                 logger.debug("Removed key "+key.kn()+" from keyring "+keyring.getPath()
                                        +" as it had passed it's max age of: "
                                        +new Date((key.va()+KEY_REMOVE_AGE)*1000L)+".");
                            }
                        }
                    }
                }
                if(modified) {
                    try {
                        saveKeys(keyring);
                        loadAndParse(keyring);
                    }
                    catch(IOException ioe) { throw new ServletException(ioe); }
                }
                else { if(logger.debug()) { logger.debug("Did not update keyring "+keyring.getPath()+"."); } }
            }
        }
        else {
            if(logger.debug()) {
                logger.debug("Not considering adding or removing keys from keyring "+keyring.getPath()
                        +", last checked: "+new Date(updateChecked)+".");
            }
        }

        // make a backup ref to the current keys in case a new keyring is loaded
        List <WebauthKey> keys = this.keys;
        List <WebauthKey> suitable = new ArrayList <WebauthKey>();
        for(WebauthKey key : keys) {
            // if the key hint is larger (i.e. more recent) than the valid-after of the key then it is suitable
            if(keyHint >= key.va() && key.va()*1000L <= now) {
                suitable.add(key);
            }
        }
        if(logger.debug()) { logger.debug("Found "+suitable.size()+" suitable keys for keyHint "+keyHint+"."); }
        return suitable;
    }
    
    
    /**
     * Saves all the keys we know about to a keyring.
     * @param   keyring The path to save the keys to.
     */
    private synchronized void saveKeys(File keyring) throws IOException {
        Writer out = null;
        try {
            out = new BufferedWriter(new FileWriter(keyring));
            out.append("v=").append(Integer.toString(v)).append(";");
            out.append("n=").append(Integer.toString(keys.size())).append(";");
            List <WebauthKey> sortedKeys = new ArrayList <WebauthKey>(keys);
            Collections.sort(sortedKeys, new Comparator <WebauthKey>() {
                public int compare(WebauthKey key1, WebauthKey key2) {
                    return key1.kn() - key2.kn();
                }
            });
            for(int i = 0; i < sortedKeys.size(); i++) {
                WebauthKey key = sortedKeys.get(i);
                out.append("ct").append(Integer.toString(i)).append("=").append(Integer.toString(key.ct())).append(";");
                out.append("va").append(Integer.toString(i)).append("=").append(Integer.toString(key.va())).append(";");
                out.append("kt").append(Integer.toString(i)).append("=").append(Integer.toString(key.kt())).append(";");
                out.append("kd").append(Integer.toString(i)).append("=").append(key.kd()).append(";");
            }
        }
        catch(IOException ioe) { logger.error(ioe.getMessage(), ioe); }
        finally {
            if(out != null) {
                try { out.close(); }
                catch(IOException ioe) { logger.error(ioe.getMessage(), ioe); }
            }
        }
        if(logger.debug()) { logger.debug("Saved "+keys.size()+" keys to the keyring: "+keyring.getPath()+"."); }
    }
    
    
    /**
     * Return the most suitable key, usually to use for encryption.
     * @return  the most suitable key to use at the moment.
     * @throws  ServletException    if there is no suitable key.
     */
    public WebauthKey mostSuitable() throws ServletException {
        List <WebauthKey> suitable = suitableKeys((int)(System.currentTimeMillis()/1000L));
        if(suitable.size() == 0) { throw new ServletException("There are no suitable keys in the keyring."); }
        WebauthKey key = suitable.get(0);
        if(logger.debug()) { logger.debug("The single most suitable key at this point in time is key "+key.kn()+"."); }
        return key;
    }
    
    
    /**
     * Loads and parses a keyring.
     * @param   keyring The keyring file to load.
     * @throws  IOException if it can't read the keyring.
     */
    private synchronized void loadAndParse(File keyring) throws IOException, ServletException {
        BufferedReader in = new BufferedReader(new FileReader(keyring));
        String[] keyData = in.readLine().split("(;|=)");
        in.close();
        int n = -1;
        int va = -1;
        int ct = -1;
        int kt = -1;
        int kn = -1;
        String kd = null;
        List <WebauthKey> newKeys = new ArrayList <WebauthKey>();
        for(int i = 0; i < keyData.length; i++) {
            switch(keyData[i].charAt(0)) {
                case 'v':   // v or va
                    if(keyData[i].length() == 1) { v = parseInt(keyData[++i]); }
                    else { va = parseInt(keyData[++i]); }
                    break;
                
                case 'n':    // n = number of keys
                    n = parseInt(keyData[++i]);
                    break;
                
                case 'c':    // ct = created time
                    // also initialise the key number
                    kn = parseInt(keyData[i].substring(2));
                    ct = parseInt(keyData[++i]);
                    break;
                
                case 'k':    // kt or kd
                    if(keyData[i].charAt(1) == 't') { kt = parseInt(keyData[++i]); }
                    else { kd = keyData[++i]; }
                    break;
                
                default:    // anything else is an error
                    throw new IOException("Received unknown token '"+keyData[i]+"' in keyring data.");
            }
            if(va!=-1 && ct!=-1 && kt!=-1 && kd!=null) {
                newKeys.add(0, new WebauthKey(kn, ct, va, kt, kd));
                va = ct = -1;
                kt = kn = -1;
                kd = null;
            }
        }
        if(newKeys.size() != n) { throw new IOException("Read "+newKeys.size()+" keys from the keyring, expected "+n); }
        if(logger.debug()) { logger.debug("Loaded "+n+" keys from the keyring."); }
        Collections.sort(newKeys);
        Collections.reverse(newKeys);
        keys = newKeys;
    }
    
    
    /** Convenience method. */
    private static int parseInt(String data) throws IOException {
        try { return Integer.parseInt(data); }
        catch(NumberFormatException nfe) {
            IOException ioe = new IOException("Could not parse '"+data+"' into an int.");
            ioe.initCause(nfe);
            throw ioe;
        }
    }

    
    /** Convenience method. */
    private static long parseLong(String data) throws IOException {
        try { return Long.parseLong(data); }
        catch(NumberFormatException nfe) {
            IOException ioe = new IOException("Could not parse '"+data+"' into a long.");
            ioe.initCause(nfe);
            throw ioe;
        }
    }
    
    
    /** Print out the keys this key manager knows about. */
    public String toString() {
        List <WebauthKey> reversedKeys = new ArrayList <WebauthKey>(keys);
        Collections.reverse(reversedKeys);
        StringBuffer sb = new StringBuffer();
        for(WebauthKey key : reversedKeys) {
            sb.append("Key:         ").append(key.kn()).append("\n");
            sb.append("Key type:    ").append(key.kt()).append("\n");
            sb.append("Created:     ").append(new Date(key.ct()*1000L)).append("\n");
            sb.append("Valid after: ").append(new Date(key.va()*1000L)).append("\n");
            sb.append("-----------------------------------------\n");
        }
        return sb.toString();
    }
}