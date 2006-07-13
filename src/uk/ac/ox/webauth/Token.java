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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;


/**
 * Codec for Webauth tokens.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class Token {

    
    /** A list of key-value pairs to add when encoding the token. */
    private final Map <String,KeyValuePair> kv = new HashMap <String,KeyValuePair> ();
    /** A Stringifier to use to return a string representing this token. */
    private Stringifier stringifier;
    /** If this is false then the token is not valid. */
    public boolean valid() { return valid; }
    private boolean valid = false;
    
    /** Somewhere to get random padding bytes from. */
    private static final Random RAND = new Random();
    /** A blank initialisation vector to use since the nonce is used as IV. */
    private static final IvParameterSpec IV = new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0});
    /** A byte holding the value of ; in US-ASCII. */
    private static final byte SEMI_COLON;
    /** A byte holding the value of = in US-ASCII. */
    private static final byte EQUALS;
    
    
    static {
        byte semiColon = 0;
        byte equals = 0;
        try {
            semiColon = ";".getBytes("US-ASCII")[0];
            equals = "=".getBytes("US-ASCII")[0];
        }
        catch(UnsupportedEncodingException uee) {
            /* US-ASCII should always exist. */
            uee.printStackTrace();
        }
        // trick the compiler into not showing not initialised errors
        SEMI_COLON = semiColon;
        EQUALS = equals;
    }
    
    
    /** Test encoding/decoding a token. */
    public static void main(String[] args) throws Exception {
        // decrypt a base64 encoded token given in args[0] with a key given in args[1]
        if(args[0] != null && args[1] != null) {
            WebauthKey secretKey = new WebauthKey(0, 0, 0, 0, args[1]);
            Token t = new Token(Base64.decodeBase64(args[0].getBytes("US-ASCII")), secretKey.key());
            System.out.println(t.toString());
            System.exit(0);
        }
        
        byte[] keyBytes = new byte[16];
        RAND.nextBytes(keyBytes);
        WebauthKey secretKey = new WebauthKey(0, 0, 0, 0, new String(Hex.encodeHex(keyBytes)));
        //SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        
        String key1 = "key1";
        String key2 = "key2";
        String key3 = "key3";
        String key4 = "key4";
        
        String data1 = "data1";
        String data2 = "data;2";
        byte[] data3 = {64,65,66,67,68,69,70,71,72,73,74};
        byte[] data4 = {64,SEMI_COLON,65,66,67,68,69,70,71,72,73,SEMI_COLON,74};
        
        Token token1 = new Token();
        token1.add(key1, data1);
        token1.add(key2, data2);
        token1.add(key3, data3);
        token1.add(key4, data4);
        String encrypted1 = token1.encrypt(secretKey.key());
        
        Token token2 = new Token();
        token2.add(key1, data1);
        token2.add(key2, data2);
        token2.add(key3, data3);
        token2.add(key4, data4);
        String encrypted2 = token2.encrypt(secretKey.key());
        if(encrypted1.equals(encrypted2)) {
            System.err.println("Two equal tokens encrypted and encoded into the same value, this is broken!");
            System.exit(1);
        }
        else { System.out.println("Two tokens with the same data do not encrypt to the same value, good."); }

        Token token3 = new Token(Base64.decodeBase64(encrypted1.getBytes("US-ASCII")), secretKey.key());
        boolean broken = false;
        if(!data1.equals(token3.getString(key1))) {
            System.err.println("data1 is different (or missing) after decryption.");
            broken = true;
        }
        if(!data2.equals(token3.getString(key2))) {
            System.err.println("data2 is different (or missing) after decryption.");
            broken = true;
        }
        if(!Arrays.equals(data3, token3.getBinary(key3))) {
            System.err.println("data3 is different (or missing) after decryption.");
            broken = true;
        }
        if(!Arrays.equals(data4, token3.getBinary(key4))) {
            System.err.println("data4 is different (or missing) after decryption.");
            broken = true;
        }
        
        if(broken) {
            System.err.println("Encryption/decryption is broken.");
            System.exit(1);
        }
        else { System.out.println("Encryption/decryption works."); }
    }
    
    
    /** Do nothing constructor. */
    public Token() {
        // XXX: this might break printing of webauth tokens
        // create the Stringifier to use
        stringifier = new KerberosTokenStringifier();
    }
    
    
    /**
     * Special constructor for a krb5 credential data token.
     * @param   data    The byte array holding the key value pairs.
     */
    public Token(byte[] data) {
        // create all the key-value pairs
        for(int i = 0, start = 0; (i = indexOf(SEMI_COLON, data, i)) != -1;) {
            i++;
            if(i < data.length && data[i] == SEMI_COLON) {
                i++;
                continue;
            }
            byte[] keyValuePairArray = new byte[i-start];
            System.arraycopy(data, start, keyValuePairArray, 0, keyValuePairArray.length);
            KeyValuePair kvp = new KeyValuePair(keyValuePairArray);
            try { kv.put(new String(kvp.key(), "US-ASCII"), kvp); }
            catch(UnsupportedEncodingException uee) {
                /* should never happen as US-ASCII must exist */
                uee.printStackTrace();
            }
            start = i;
        }
        valid = true;
            
        // create the Stringifier to use
        stringifier = new KerberosTokenStringifier();
    }
     

    /**
     * Initialise a token with a base64 encoded Webauth token.
     * @param   tokenData   The data to be decrypted.
     * @param   sessionKey  The session key to use for the AES and Hmac.
     * @throws  GeneralSecurityException    if there was a problem with the security code used.
     */
    public Token(byte[] tokenData, Key sessionKey) throws GeneralSecurityException {
        // a token is:
        // {key-hint}{nonce   }{hmac    }{token-attributes     }{padding         }
        // {4 bytes }{16 bytes}{20 bytes}{make the data into multiple of 16 bytes}
        // everything after the key hint is aes encrypted
        
        try {
            // set up some streams
            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(tokenData);
            DataInputStream dataInputStream = new DataInputStream(byteArrayInputStream);
            
            // read the key hint
            int keyHint = dataInputStream.readInt();
            
            // prepare to AES decrypt the rest
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(DECRYPT_MODE, sessionKey, IV);
            CipherInputStream decrypt = new CipherInputStream(byteArrayInputStream, cipher);
            
            // throw away the nonce
            if(decrypt.read(new byte[16]) != 16) {
                throw new GeneralSecurityException("Failed to read nonce from token.");
            }
            
            // read the HMACSHA1 checksum
            byte[] checksum = new byte[20];
            if(decrypt.read(checksum) != 20) {
                throw new GeneralSecurityException("Failed to read HMAC SHA1 checksum from token.");
            }
            
            // read in the rest of the data
            ByteArrayOutputStream tokenByteArrayOutputStream = new ByteArrayOutputStream();
            for(int b = decrypt.read(); b != -1; b = decrypt.read()) { tokenByteArrayOutputStream.write(b); }
            byte[] data = tokenByteArrayOutputStream.toByteArray();
            decrypt.close();
            
            // check the hmacsha1
            Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
            hmacSHA1.init(sessionKey);
            if(!Arrays.equals(checksum, hmacSHA1.doFinal(data))) {
                throw new GeneralSecurityException("Invalid token, checksum mismatch.");
            }
            
            // create all the key-value pairs
            for(int i = 0, start = 0; (i = indexOf(SEMI_COLON, data, i)) != -1;) {
                i++;
                if(i < data.length && data[i] == SEMI_COLON) {
                    i++;
                    continue;
                }
                byte[] keyValuePairArray = new byte[i-start];
                System.arraycopy(data, start, keyValuePairArray, 0, keyValuePairArray.length);
                KeyValuePair kvp = new KeyValuePair(keyValuePairArray);
                kv.put(new String(kvp.key(), "US-ASCII"), kvp);
                start = i;
            }
        }
        catch(IOException ioe) {
            /* should never happen as it's a ByteArrayInputStream */
            ioe.printStackTrace();
        }
        valid = true;
            
        // create the Stringifier to use
        stringifier = new WebauthTokenStringifier();
    }
    
    
    /**
     * Add a key and value pair. No need to do any escaping, it's done
     * automagically. The strings must be in US-ASCII otherwise the result is
     * undefined.
     * @param   key     The name of the key for this value.
     * @param   value   The value.
     */
    public void add(String key, String value) {
        try { kv.put(key, new KeyValuePair(key.getBytes("US-ASCII"), value.getBytes("US-ASCII"))); }
        catch(UnsupportedEncodingException uee) {
            /* should never happen as US-ASCII must exist in a Java impl. */
            uee.printStackTrace();
        }
    }
    
    
    /**
     * Add a key and value pair. No need to do any escaping, it's done
     * automagically. The strings must be in US-ASCII otherwise the result is
     * undefined.
     * @param   key     The name of the key for this value.
     * @param   value   The byte array that holds the binary value.
     */
    public void add(String key, byte[] value) {
        try { kv.put(key, new KeyValuePair(key.getBytes("US-ASCII"), value)); }
        catch(UnsupportedEncodingException uee) {
            /* should never happen as US-ASCII must exist in a Java impl. */
            uee.printStackTrace();
        }
    }
    
    
    /**
     * Return all the key names.
     * @return  a set with all the key names.
     */
    public Set <String> keySet() { return Collections.unmodifiableSet(kv.keySet()); }
    
    
    /**
     * Return the corresponding String for a key, if present in the token. This
     * is a relatively expensive operation.
     * @param   key The key to look for a value fur.
     * @return  the value as a String, or null if not available. Note that if
     *          the value is actually some binary data the result will be undefined.
     */
    public String getString(String key) {
        byte[] data = getBinary(key);
        try { return (data == null) ? null : new String(data, "US-ASCII"); }
        catch(UnsupportedEncodingException uee) {
            /* should never happen as US-ASCII must exist in a Java impl. */
            uee.printStackTrace();
        }
        return null;    // since there must always be a return
    }
    
    
    /**
     * Return the corresponding array of binary data for a key, if present in
     * the token. This is a relatively expensive operation.
     * @param   key The key to look for a value fur.
     * @return  the value as an array of bytes.
     */
    public byte[] getBinary(String key) {
        KeyValuePair kvp = kv.get(key);
        return (kvp == null) ? null : kvp.value();
    }
    
    
    /**
     * Encode the token and return it.
     * @param   sessionKey  The session key to use to AES encrypt and feed the HMAC.
     * @return  The escaped, encrypted and base64 encoded token.
     * @throws  GeneralSecurityException    if there was a problem with the security code used.
     */
    public String encrypt(Key sessionKey) throws GeneralSecurityException {
        // a token is:
        // {key-hint}{nonce   }{hmac    }{token-attributes     }{padding         }
        // {4 bytes }{16 bytes}{20 bytes}{make the data into multiple of 16 bytes}
        // everything after the key hint is aes encrypted
        
        // this is where we want to final data packet to end up
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        try {
            data.write(unixTimestampBytes(System.currentTimeMillis()));
            
            // set up the AES encryption
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(ENCRYPT_MODE, sessionKey, IV);
            CipherOutputStream encrypt = new CipherOutputStream(data, cipher);
            
            // write the nonce
            byte[] nonce = new byte[16];
            RAND.nextBytes(nonce);
            encrypt.write(nonce);
            
            // put together the actual key-value pair data to send
            ByteArrayOutputStream paddedKeyValueData = new ByteArrayOutputStream();
            for(KeyValuePair kvp : kv.values()) { paddedKeyValueData.write(kvp.bytes()); }
            
            // and pad it (including the size of the hmac to be added later)
            int padding = 16-((20+paddedKeyValueData.size())%16);
            for(int i = 0; i < padding; i++) { paddedKeyValueData.write(padding); }
            byte[] paddedKeyValueDataArray = paddedKeyValueData.toByteArray();
            
            // then work out and write the SHA1 HMAC
            Mac hmacSHA1 = Mac.getInstance("HmacSHA1");
            hmacSHA1.init(sessionKey);
            encrypt.write(hmacSHA1.doFinal(paddedKeyValueDataArray));
            
            // then write the actual key-value pair data and padding and close it
            encrypt.write(paddedKeyValueDataArray);
            encrypt.close();
        }
        catch(IOException ioe) {
            /* should never happen as it's a ByteArrayOutputStream */
            ioe.printStackTrace();
        }
        
        // return the token after base64 encoding it
        return new String(Base64.encodeBase64(data.toByteArray()));
    }
    
    
    /**
     * Convenience method for getting a byte array with a unix timestamp, i.e.
     * number of seconds since the epoch.
     * @param   date    The date to base the timestamp on.
     * @return  A unix time stamp in an integer saved in network byte order in
     *          a byte array.
     */
    public static byte[] unixTimestampBytes(Date date) {
        return unixTimestampBytes(date.getTime());
    }
    
    
    /**
     * Convenience method for getting a byte array with a unix timestamp, i.e.
     * number of seconds since the epoch.
     * @param   date    The date to base the timestamp on, such as System.currentTimeMillis().
     * @return  A unix time stamp in an integer saved in network byte order in
     *          a byte array.
     */
    public static byte[] unixTimestampBytes(long date) {
        ByteArrayOutputStream arrayStream = new ByteArrayOutputStream();
        try {
            DataOutputStream dataStream = new DataOutputStream(arrayStream);
            dataStream.writeInt((int)(date/1000L));
        }
        catch(IOException ioe) {
            /* should never happen as it's a ByteArrayOutputStream */
            ioe.printStackTrace();
        }
        return arrayStream.toByteArray();
    }
    
    
    /**
     * Turn a byte array into an int.
     * @param   bytes   The bytes to turn into an int.
     * @return  An Integer number, or null if there is a problem.
     */
    public static Integer bytesToInt(byte[] bytes) {
        if(!(bytes.length == 4)) { return null; }
        DataInputStream in = new DataInputStream(new ByteArrayInputStream(bytes));
        try { return in.readInt(); }
        catch(IOException ioe) {
            ioe.printStackTrace();
            return null;
        }
    }
    
    
    /**
     * Turn a byte array with a unix timestamp into a Date.
     * @param   bytes   A byte array of length 4 containing an int representing
     *          a unix timestamp, i.e. number of seconds since the epoch.
     * @return  a Date representing the unix timestamp, or null if the timestamp
     *          is somehow invalid.
     */
    public static Date bytesToDate(byte[] bytes) {
        Integer n = bytesToInt(bytes);
        if(n == null) { return null; }
        return new Date(n*1000L);
    }
    
    
    /**
     * Return the index of a byte in an array.
     * @param   b       The byte to search for in the array.
     * @param   data    The byte array to search in.
     * @param   offset  The index (inclusive) to start the search at.
     * @return  the index where the byte was found, or -1 if it wasn't found.
     */
    private static int indexOf(byte b, byte[] data, int offset) {
        int index = -1;
        for(int i = offset; i < data.length; i++) {
            if(data[i] == b) {
                index = i;
                break;
            }
        }
        return index;
    }

    
    /**
     * Escape all ; in the data.
     * @param   data    The data to escape.
     * @return  the escaped data.
     */
    private static byte[] escape(byte[] data) {
        ByteArrayOutputStream escaped = new ByteArrayOutputStream();
        for(int i = 0; i < data.length; i++) {
            if(data[i] == SEMI_COLON) { escaped.write(SEMI_COLON); }
            escaped.write(data[i]);
        }
        return escaped.toByteArray();
    }
    
    
    /**
     * Unescape all ;; in the data, and chop off the last ;.
     * @param   data    The data to unescape.
     * @param   offset  Start at this index in the data array;
     * @return  the unescaped data.
     */
    private static byte[] unescape(byte[] data, int offset) {
        ByteArrayOutputStream unescaped = new ByteArrayOutputStream();
        int dataLength = data.length-1;     // don't read the last ;
        for(int i = offset; i < dataLength; i++) {
            unescaped.write(data[i]);
            if(data[i] == SEMI_COLON) { i++; }
        }
        return unescaped.toByteArray();
    }
    
    
    /**
     * Return a String describing this token.
     * @return  a string describing the token.
     */
    public String toString() { return stringifier.toString(this); }



    /** A class to delegate key and value pairs to. */
    private static class KeyValuePair {
        
        /** The key bytes. */
        public byte[] key() { return key; }
        private byte[] key;
        /** The value bytes. */
        public byte[] value() { return value; }
        private byte[] value;
        
        /**
         * Pass in an escaped key-value pair byte array and it parses it into a
         * key and value.
         * @param   data    An escaped array with the key and the value, terminated 
         *          with a semicolon.
         */
        public KeyValuePair(byte[] data) {
            int equalsIndex = indexOf(EQUALS, data, 0);
            key = new byte[equalsIndex];
            System.arraycopy(data, 0, key, 0, equalsIndex);
            value = unescape(data, equalsIndex+1);
        }
        
        /**
         * Take the data and escape all ; in it.
         * @param   key     The key for the data.
         * @param   value   The bytes for the value.
         */
        public KeyValuePair(byte[] key, byte[] value) {
            this.key = key;
            this.value = value;
        }
        
        /**
         * Return the escaped bytes for this key-value pair.
         * @return  the escaped bytes.
         */
        public byte[] bytes() {
            ByteArrayOutputStream escaped = new ByteArrayOutputStream();
            try {
                escaped.write(key);
                escaped.write(EQUALS);
                escaped.write(escape(value));
                escaped.write(SEMI_COLON);
            }
            catch(IOException ioe) {
                /* should never happen as it's a ByteArrayOutputStream */
                ioe.printStackTrace();
            }
            return escaped.toByteArray();
        }
    }
    
    
    /** Interface to make the objects that turn a token into a string. */
    private static interface Stringifier {
        /** Turn a token into a string. */
        public String toString(Token t);
    }
    
    
    /** Class to stringify a regular Webauth token. */
    private static class WebauthTokenStringifier implements Stringifier {

        /** An unmodifiable Set holding all names of tokens that are Strings. */
        private static final Set STRING_TOKENS;
        /** An unmodifiable Set holding all names of tokens that are arrays of binary data. */
        private static final Set BINARY_TOKENS;
        /** An unmodifiable Set holding all names of tokens that are arrays of binary data representing a timestamp. */
        private static final Set DATE_TOKENS;

        static {
            // initialise things for the toString() method
            String[] stringTokens = {"cmd",
                                     "crs",
                                     "crt",
                                     "ec",
                                     "em",
                                     "p",
                                     "ps",
                                     "pt",
                                     "ro",
                                     "rtt",
                                     "ru",
                                     "s",
                                     "sa",
                                     "t",
                                     "u"
            };
            Set <String> strings = new TreeSet <String>();
            for(String s : stringTokens) { strings.add(s); }
            STRING_TOKENS = Collections.unmodifiableSet(strings);
            
            String[] binaryTokens = {"as",
                                     "crd",
                                     "k",
                                     "pd",
                                     "sad",
                                     "wt"
            };
            Set <String> binary = new TreeSet <String>();
            for(String s : binaryTokens) { binary.add(s); }
            BINARY_TOKENS = Collections.unmodifiableSet(binary);
    
            String[] dateTokens = {"ct",
                                   "et",
                                   "lt"
            };
            Set <String> dates = new TreeSet <String>();
            for(String s : dateTokens) { dates.add(s); }
            DATE_TOKENS = Collections.unmodifiableSet(dates);
        }

        public String toString(Token t) {
            StringBuilder string = new StringBuilder();
            string.append("Webauth token keys and values:\n");
            for(String key : t.kv.keySet()) {
                string.append(key).append(": ");
                if(STRING_TOKENS.contains(key)) {
                    string.append("'")
                            .append(t.getString(key))
                            .append("'");
                }
                else if(BINARY_TOKENS.contains(key)) {
                    string.append("binary value, ")
                            .append(t.getBinary(key).length)
                            .append(" bytes, value: ")
                            .append(new String(Hex.encodeHex(t.getBinary(key))));
                }
                else if(DATE_TOKENS.contains(key)) {
                    string.append(bytesToDate(t.getBinary(key)));
                }
                else {
                    string.append("unknown type, ")
                            .append(t.getBinary(key).length)
                            .append(" bytes");
                }
                string.append("\n");
            }
            return string.toString().substring(0, string.length()-1);
        }
    }
    
    
    /** Class to stringify a Kerberos credential token. */
    private static class KerberosTokenStringifier implements Stringifier {

        /** An unmodifiable Set holding all names of tokens that are Strings. */
        private static final Set STRING_TOKENS;
        /** An unmodifiable Set holding all names of tokens that are arrays of binary data. */
        private static final Set BINARY_TOKENS;
        /** An unmodifiable Set holding all names of tokens that are arrays of binary data representing a timestamp. */
        private static final Set DATE_TOKENS;
        /** An unmodifiable Set holding all names of tokens that are arrays of binary data representing an integer. */
        private static final Set NUMBER_TOKENS;
        

        static {
            // initialise things for the toString() method
            String[] stringTokens = {"c",
                                     "s"
            };
            Set <String> strings = new TreeSet <String>();
            for(String s : stringTokens) { strings.add(s); }
            STRING_TOKENS = Collections.unmodifiableSet(strings);
            
            String[] binaryTokens = {"a",
                                     "k",
                                     "t"
            };
            Set <String> binary = new TreeSet <String>();
            for(String s : binaryTokens) { binary.add(s); }
            BINARY_TOKENS = Collections.unmodifiableSet(binary);
    
            String[] dateTokens = {"ta",
                                   "te",
                                   "tr",
                                   "ts"
            };
            Set <String> dates = new TreeSet <String>();
            for(String s : dateTokens) { dates.add(s); }
            DATE_TOKENS = Collections.unmodifiableSet(dates);
            
            String[] integerTokens = {"A",
                                      "D",
                                      "d",
                                      "f",
                                      "i",
                                      "K",
                                      "na",
                                      "nd"
            };
            Set <String> integers = new TreeSet <String>();
            for(String s : integerTokens) { integers.add(s); }
            NUMBER_TOKENS = Collections.unmodifiableSet(integers);
        }

        public String toString(Token t) {
            StringBuilder string = new StringBuilder();
            string.append("Kerberos token keys and values:\n");
            for(String key : t.kv.keySet()) {
                String searchKey = key.replaceFirst("[\\d]+$", "");
                string.append(key).append(": ");
                if(STRING_TOKENS.contains(searchKey)) {
                    string.append("'")
                            .append(t.getString(key))
                            .append("'");
                }
                else if(BINARY_TOKENS.contains(searchKey)) {
                    string.append("binary value, ")
                            .append(t.getBinary(key).length)
                            .append(" bytes, value: ")
                            .append(new String(Hex.encodeHex(t.getBinary(key))));
                }
                else if(DATE_TOKENS.contains(searchKey)) {
                    string.append(bytesToDate(t.getBinary(key)));
                }
                else if(NUMBER_TOKENS.contains(searchKey)) {
                    string.append(bytesToInt(t.getBinary(key)));
                }
                else {
                    string.append("unknown type, ")
                            .append(t.getBinary(key).length)
                            .append(" bytes");
                }
                string.append("\n");
            }
            return string.toString().substring(0, string.length()-1);
        }
    }
}