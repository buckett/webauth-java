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
import java.io.DataInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ac.ox.webauth.tokenvalidators.IdTV;
import uk.ac.ox.webauth.tokenvalidators.ProxyTV;
import uk.ac.ox.webauth.tokenvalidators.Validator;

import static uk.ac.ox.webauth.tokenvalidators.Validator.FIVE_MINUTES;


/**
 * Servlet Filter that Webauth authenticates a person.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class FilterWorker {
    
    
    /** The users username once we have found out what it is. */
    private String username;
    /** The remote ip address of this request. */
    private String rip;
    /** The request object. */
    private HttpServletRequest request;
    /** The response object. */
    private HttpServletResponse response;
    /** The FilterChain. */
    private FilterChain chain;
    /** The URL to redirect people to in order to authenticate them. */
    private String webAuthLoginURL;
    /** The config to use for this filter. */
    private FilterConfig config;
    /** Log to this. */
    private LogWrapper logger;
    /** The private WAS AES key manager. */
    private PrivateKeyManager privateKeyManager;
    /** The most suitable key for this request to encrypt things with. */
    private WebauthKey privateKey;
    /** The session key that is shared with the WebKDC. */
    private SecretKey sessionKey;
    /** The service token base64 data. */
    private String serviceToken;
    /** A Map to temporary hold all the data needed for JAAS. */
    private Map <Thread,Filter.JAASData> jaas;
    /** The Webauth related cookies from this request. */
    private Map <String,Cookie> cookies = new HashMap <String,Cookie>();
    

    public FilterWorker(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            FilterConfig config, LogWrapper logger, PrivateKeyManager privateKeyManager,
            Map <Thread,Filter.JAASData> jaas, String serviceToken, SecretKey sessionKey) {
        this.request = request;
        this.response = response;
        this.chain = chain;
        this.config = config;
        this.logger = logger;
        this.privateKeyManager = privateKeyManager;
        this.jaas = jaas;
        this.serviceToken = serviceToken;
        this.sessionKey = sessionKey;
        webAuthLoginURL = config.getInitParameter("WebAuthLoginURL");
        rip = request.getRemoteAddr();
        if(request.getCookies() != null) {
            for(Cookie c : request.getCookies()) {
                cookies.put(c.getName(), c);
            }
        }
    }


    /**
     * Checks if the user is allowed through, and redirects to the WebKDC if
     * they are not.
     */
    public void run() throws ServletException, IOException {
        long start = System.currentTimeMillis();
                
        // grab the best encryption key here and reuse it several times
        privateKey = privateKeyManager.mostSuitable();

        // first check if the user was just redirected back from the WebKDC, i.e. they have a WEBAUTHR param
        String queryString = request.getQueryString();
        if(queryString != null && queryString.contains("WEBAUTHR=")) {
            debug("Received a WEBAUTHR token.");
            Token webauthr;
            if(queryString.contains("WEBAUTHS=")) {
                Token webauths = webauthsToken(request);
                webauthr = webauthrToken(request, new SecretKeySpec(webauths.getBinary("k"), "AES"));
                debug("Used a WEBAUTHS token to decrypt the WEBAUTHR token.");
            }
            else { webauthr = webauthrToken(request, sessionKey); }
            if(logger.debug()) { debug("WEBAUTHR token: "+webauthr.toString()); }
            Validator v = Validator.isProxyToken(webauthr)
                    ? new ProxyTV(webauthr, logger) : new IdTV(sessionKey, webauthr, logger);
            if(v.valid()) {
                username = webauthr.getString("s");
                setAppCookie(webauthr, privateKey, response);
                setProxyCookie(webauthr, privateKey, response);
                debug("Authenticated client.");
            }
            else { debug("Recieved an invalid WEBAUTHR token."); }
            
            // do an extra redirect so that the WEBAUTH params are not visible in the URL
            if(username != null && Boolean.parseBoolean(config.getInitParameter("WebAuthExtraRedirect"))) {
                extraRedirect(new RequestWrapper(request));
                if(logger.debug()) { debug("Request took "+(System.currentTimeMillis()-start)+" milliseconds.");}
                return;
            }
        }
        
        // if the user wasn't just redirected back from a WebKDC then check if they have an app cookie already
        if(username == null && cookies.containsKey("webauth_at")) {
            // TODO: clean this up to be more in line with above
            debug("Received an app-token cookie.");
            handleAppCookie(privateKey);
        }

        request = new RequestWrapper(request, username);
        // if we still have no username then redirect the user to the WebKDC
        if(username == null) {
            redirect();
            if(logger.debug()) { debug("Request took "+(System.currentTimeMillis()-start)+" milliseconds."); }
            return;
        }
        // only let the request progress to other filters and to the final
        // destination if they have been authenticated, i.e. we have a username
        else {
            boolean useJAAS = Boolean.parseBoolean(config.getInitParameter("UseJAAS"));
            IOException ioe = null;
            ServletException se = null;
            try {
                if(useJAAS) {
                    // grab any proxy credentials needed
                    List <Token> tickets = new ArrayList <Token>();
                    if(gotAllProxyCreds(tickets, privateKey)) { debug("Found all necessary proxy credentials."); }
                    else {
                        redirect();
                        if(logger.debug()) {
                            debug("Request took "+(System.currentTimeMillis()-start)+" milliseconds.");
                        }
                        return;
                    }
                    // set the JAAS data for the user
                    jaas.put(Thread.currentThread(), new Filter.JAASData(username, tickets));
                }
                else { debug("Not using JAAS so not putting any JAAS data in."); }
    
                if(logger.debug()) {
                    debug("-------- Letting authenticated client through.");
                    debug("Request took "+(System.currentTimeMillis()-start)+" milliseconds.");
                }
                chain.doFilter(request, response);
            }
            // make sure that whatever happens the jaas data gets removed so we don't leak memory at exceptions
            catch(ServletException e) { se = e; }
            catch(IOException e) { ioe = e; }
            finally {
                if(useJAAS) {
                    // clean out the JAAS data once the filter chain has completed
                    jaas.remove(Thread.currentThread());
                }
                if(se != null) { throw se; }
                if(ioe != null) { throw ioe; }
            }
        }
    }
    
    
    /** Print a debug message in the log but prepend ip and username. */
    private void debug(String message) { logger.debug(rip+((username == null) ? "" : ":"+username)+": "+message); }
    
    
    /**
     * Acquire any proxy tokens needed, either from already present cookies, or
     * by requesting them from the WebKDC. This method has been implemented in
     * the spirit of Webauth being able to support different cred types, even
     * though at the moment it only supports krb5 creds.
     * @param   tickets     A List where all proxu credential tokens are to be placed.
     * @param   privateKey  The key most likely needed to decrypt any cookies.
     * @return  Returns true if it is not necessary to redirect the user to get
     *          a proxy token.
     */
    private boolean gotAllProxyCreds(List <Token> tickets, WebauthKey privateKey) throws ServletException {
        // if no tickets are required then just return
        if(config.getInitParameter("ProxyCredentials") == null) { return true; }

        // get the services for which tickets are required
        Map <String,String> services = new HashMap <String,String>();
        for(String serviceLine : config.getInitParameter("ProxyCredentials").split(",")) {
            String[] credService = serviceLine.trim().split(" ", 2);
            services.put(credService[1].trim(), credService[0].trim());
        }
        if(logger.debug()) {
            debug("Needs the following proxy credentials:");
            for(String service : services.keySet()) { debug("    "+services.get(service)+" "+service); }
        }
        
        // check if we have a valid cred token for any of the services already
        Map <String,String> missing = new HashMap <String,String>();
        for(String service : services.keySet()) {
            String type = services.get(service);
            String webauth_ct = "webauth_ct_"+type+"_"+service;
            if(logger.debug()) { debug("Checking for cred cookie: "+webauth_ct+"."); }
            Cookie c = cookies.get(webauth_ct);
            if(c == null) { missing.put(service, type); }
            else {
                // the decrypt method will validate the token and throw an exception if it is invalid
                // if it is invalid then don't add it so it will be requested instead
                try {
                    Token cred = decrypt(c.getValue(), "cred");
                    if(username.equals(cred.getString("s"))) {
                        tickets.add(new Token(cred.getBinary("crd")));
                        if(logger.debug()) { debug("Client has valid cred token: "+type+" "+service+"."); }
                    }
                    else {
                        if(logger.debug()) {
                            debug("Found a cred token for "+type+" "+service+" with username "+cred.getString("s")+".");
                        }
                    }
                }
                catch(ServletException se) {
                    missing.put(service, type);
                    if(logger.debug()) { debug("Found an invalid cred token for: "+type+" "+service+"."); }
                }
            }
        }

        // request any missing tokens
        if(missing.size() == 0) { debug("Found all required proxy tokens."); }
        else {
            if(logger.debug()) {
                debug("Missing cred tokens for services:");
                for(String service : missing.keySet()) { debug("    "+missing.get(service)+" "+service+"."); }
            }
            // make sure we have all required proxy tokens to get proxy creds
            List <Token> proxyTokens = new ArrayList <Token>();
            for(String type : new HashSet <String> (missing.values())) {
                String webauth_pt = "webauth_pt_"+type;
                Cookie c = cookies.get(webauth_pt);
                if(c == null) {
                    debug("Did not find all necessary proxy tokens.");
                    return false;
                }
                else {
                    // the decrypt method will validate the token and throw an exception if it is invalid
                    Token proxy = null;
                    try { proxy = decrypt(c.getValue(), "proxy"); }
                    catch(ServletException se) {
                        return false;
                    }
                    if(username.equals(proxy.getString("s"))) {
                        proxyTokens.add(proxy);
                        if(logger.debug()) { debug("Found valid proxy token of type: "+type+"."); }
                    }
                    else { if(logger.debug()) { debug("Found a proxy token with username "+proxy.getString("s")+"."); }}
                }
            }
            
            // then request all the missing creds and add them as cookies
            List <Token> creds = requestProxyCredentials(missing, proxyTokens);
            for(Token t : creds) {
                tickets.add(new Token(t.getBinary("crd")));
                try {
                    Cookie webauth_ct = new Cookie("webauth_ct_"+t.getString("crt")+"_"+t.getString("crs"),
                            t.encrypt(privateKey.key()));
                    webauth_ct.setMaxAge(-1);
                    webauth_ct.setSecure(true);
                    webauth_ct.setPath("/");
                    response.addCookie(webauth_ct);
                    cookies.put(webauth_ct.getName(), webauth_ct);
                    if(logger.debug()) {
                        debug("Added proxy cred token cookie '"+webauth_ct.getName()+"'.");
                        debug(t.toString());
                    }
                }
                catch(GeneralSecurityException gse) {throw new ServletException("Could not encrypt cred cookie.", gse);}
            }
        }
        
        // add a tgt since java is broken
        if(Boolean.parseBoolean(config.getInitParameter("AddFakeTGT"))) {
            addFakeTGT(((KerberosPrincipal)request.getUserPrincipal()).getRealm(), tickets);
        }
        return true;
    }
    
    
    /**
     * Current Java (1.5) implementations are a bit broken, and so they will
     * always try to get a TGT before looking if there is already a credential
     * to use. This just adds a fake one in order to stop it doing that.
     * @param   realm   The realm to base the TGT on.
     * @param   tickets All the already existing ticket tokens.
     */
    public void addFakeTGT(String realm, List <Token> tickets) {
        if(tickets.size() == 0) { return; }
        debug("Adding a fake TGT.");
        Token t = tickets.get(0);
        Token tgt = new Token();
        for(String key : t.keySet()) {
            tgt.add(key, t.getBinary(key));
        }
        tgt.add("s", "krbtgt/"+realm+"@"+realm);
        tickets.add(tgt);
    }


    /**
     * Request any proxy credentials this user needs.
     * @param   missing     The missing credentials, service mapped to type.
     * @param   proxyTokens The webkdc-proxy tokens to use to get the creds.
     * @return  a list of tokens containing the new credentials.
     * @throws  ServletException    if something goes wrong.
     */
    private List <Token> requestProxyCredentials(Map <String,String> missing, List <Token> proxyTokens)
            throws ServletException {
        /*
        <getTokensRequest>
          <requesterCredential type="service">{base64-webkdc-service-token}</requesterCredential>
          <subjectCredential type="proxy">
            <proxyToken>{base64-webkdc-proxy-token}</proxyToken>
          </subjectCredential>
          <requestToken>{base64-request-token}</requestToken>
          <tokens>
            <token type="cred" id="0">
              <credentialType>krb5</credentialType>
              <serverPrincipal>foo/bar.institution.ac.uk@INSTITUTION.AC.UK</serverPrincipal>
            </token>
          </tokens>
        </getTokensRequest>
        */
        // first build the request string
        StringBuilder sb = new StringBuilder();
        sb.append("<getTokensRequest><requesterCredential type=\"service\">")
                .append(serviceToken)
                .append("</requesterCredential><subjectCredential type=\"proxy\">");
        for(Token proxy : proxyTokens) {
            sb.append("<proxyToken>")
                    .append(new String(Base64.encodeBase64(proxy.getBinary("wt"))))
                    .append("</proxyToken>");
        }
        sb.append("</subjectCredential><requestToken>");
        Token rt = new Token();
        rt.add("t", "req");
        rt.add("ct", Token.unixTimestampBytes(System.currentTimeMillis()));
        rt.add("cmd", "getTokensRequest");
        try { sb.append(rt.encrypt(sessionKey)); }
        catch(GeneralSecurityException gse) {
            throw new ServletException("Could not encrypt request token for a proxy cred request.", gse);
        }
        sb.append("</requestToken><tokens>");
        int index = 0;
        for(String service : missing.keySet()) {
            sb.append("<token type=\"cred\" id=\"")
                    .append(index++)
                    .append("\"><credentialType>")
                    .append(missing.get(service))
                    .append("</credentialType><serverPrincipal>")
                    .append(service)
                    .append("</serverPrincipal></token>");
        }
        sb.append("</tokens></getTokensRequest>");
        debug("Requesting proxy creds from the WebKDC.");
        WebKdcXmlRequest wkxr = new WebKdcXmlRequest(config.getInitParameter("WebAuthWebKdcURL"));
        Document doc = null;
        try { doc = wkxr.doPost(sb.toString()); }
        catch(IOException ioe) { throw new ServletException("Could not post proxy cred request to WebKDC.", ioe); }
        
        /*
        <getTokensResponse>
          <tokens>
            <token id="0">
              <tokenData>{proxy-cred-token-base64}</tokenData>
            </token>
            <token id="1">
              <tokenData>{proxy-cred-token-base64}</tokenData>
            </token>
            <.../>
          </tokens>
        </getTokensResponse>
        */
        List <Token> creds = new ArrayList <Token>();
        Node tokens = doc.getDocumentElement().getFirstChild();
        if(!"tokens".equals(tokens.getNodeName())) {
            throw new ServletException("XML response is not in expected format, element name is '"
                +tokens.getNodeName()+"', was expecting 'tokens'.");
        }
        NodeList children = tokens.getChildNodes();
        for(int i = 0; i < children.getLength(); i++) {
            Node token = children.item(i);
            if(!"token".equals(token.getNodeName())) {
                throw new ServletException("XML response is not in expected format, element name is '"
                    +token.getNodeName()+"', was expecting 'token'.");
            }
            Node tokenData = token.getFirstChild();
            if(!"tokenData".equals(tokenData.getNodeName())) {
                throw new ServletException("XML response is not in expected format, element name is '"
                    +tokenData.getNodeName()+"', was expecting 'tokenData'.");
            }
            String base64data = tokenData.getFirstChild().getNodeValue();
            try { creds.add(new Token(base64decode(base64data), sessionKey)); }
            catch(GeneralSecurityException gse) {throw new ServletException("Could not decode proxy cred token.", gse);}
        }
        /*
        try {
            StringWriter sw = new StringWriter();
            StreamResult streamResult = new StreamResult(sw);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer serializer = tf.newTransformer();
            serializer.setOutputProperty(OutputKeys.ENCODING,"UTF-8");
            serializer.setOutputProperty(OutputKeys.INDENT,"yes");
            serializer.transform(new DOMSource(doc), streamResult);
            debug("Received from the WebKDC: "+sw.toString());
        }
        catch(Exception e) {
            throw new ServletException(e);
        }
        */
        return creds;
    }
    
    
    /**
     * Try to decrypt a token, first with the key given, and then with any key
     * we know about, throwing an exception if we don't succeed.
     * @param   base64data  The Base64 encoded data of a token.
     * @param   type        What type of token this is to validate it as.
     * @return  A validated token.
     * @throws  ServletException    if it wasn't possible to encrypt or validate
     *          the token.
     */
    private Token decrypt(String base64data, String type) throws ServletException {
        Token token = null;
        byte[] tokenData = base64decode(base64data);
        // first try with the given key
        try {
            token = new Token(tokenData, privateKey.key());
            if(logger.debug()) { debug("Decrypted '"+type+"' type token with key "+privateKey.kn()+"."); }
        }
        catch(GeneralSecurityException gse) {
            if(logger.debug()) { debug("Could not decrypt "+type+" type token with supplied key "+privateKey.kn()+".");}
        }
        // otherwise try with every other private key we know of
        if(token == null) {
            List <WebauthKey> suitable = null;
            try {
                DataInputStream din = new DataInputStream(new ByteArrayInputStream(tokenData));
                suitable = privateKeyManager.suitableKeys(din.readInt());
            }
            catch(IOException ioe) {
                // should never happen since it's a ByteArrayInputStream
                throw new ServletException(ioe);
            }
            suitable.remove(privateKey);
            for(WebauthKey wk : suitable) {
                try { token = new Token(tokenData, wk.key()); }
                catch(GeneralSecurityException gse) {
                    if(logger.debug()) { debug("Could not decrypt '"+type+"' type token with key "+wk.kn()+"."); }
                }
                if(token != null) {
                    if(logger.debug()) { debug("Decrypted '"+type+"' type token with key "+wk.kn()+"."); }
                    break;
                }
            }
        }
        if(token == null) { throw new ServletException("Could not decrypt '"+type+"' type token with any key."); }
        
        // now validate the token
        if(!Validator.validate(type,token,logger)){ throw new ServletException("'"+type+"' token does not validate."); }
        return token;
    }
    
    
    /**
     * Set a proxy cookie authenticating the user to this WAS.
     * @param   webauthr    The users WEBAUTHR token.
     * @param   privateKey  The private WAS key to encrypt the proxy cookie with.
     * @param   response    The response object to send the cookie to.
     */
    private void setProxyCookie(Token webauthr, WebauthKey privateKey, HttpServletResponse response)
            throws ServletException {
        // if the webauthr token is a proxy token then set a cookie containing it
        if(!"proxy".equals(webauthr.getString("t"))) { return; }
        String encrypted = null;
        try { encrypted = webauthr.encrypt(privateKey.key()); }
        catch(GeneralSecurityException gse) { throw new ServletException("Could not encrypt proxy-token.", gse);}
        Cookie webauth_pt = new Cookie("webauth_pt_"+webauthr.getString("pt"), encrypted);
        webauth_pt.setMaxAge(-1);
        webauth_pt.setSecure(true);
        webauth_pt.setPath("/");
        response.addCookie(webauth_pt);
        cookies.put(webauth_pt.getName(), webauth_pt);
    }


    /**
     * Set an app cookie authenticating the user to this WAS.
     * @param   webauthr    The users WEBAUTHR token.
     * @param   privateKey  The private WAS key to encrypt the app cookie with.
     * @param   response    The response object to send the cookie to.
     */
    private void setAppCookie(Token webauthr, WebauthKey privateKey, HttpServletResponse response)
            throws ServletException {
        // set a cookie containing an app-token identifying the user
        Token app = new Token();
        app.add("t", "app");
        app.add("s", webauthr.getString("s"));
        app.add("et", webauthr.getBinary("et"));
        app.add("ct", Token.unixTimestampBytes(System.currentTimeMillis()));
        // If we want the last-used time to be updated it means the cookie has to be reencrypted each time that
        // is done, and that costs cpu time, so disabled for now.
        //app.add("lt", now);
        String encrypted = null;
        try { encrypted = app.encrypt(privateKey.key()); }
        catch(GeneralSecurityException gse) { throw new ServletException("Could not encrypt app-token.", gse);}
        Cookie webauth_at = new Cookie("webauth_at", encrypted);
        webauth_at.setMaxAge(-1);
        webauth_at.setSecure(true);
        webauth_at.setPath("/");
        response.addCookie(webauth_at);
        cookies.put(webauth_at.getName(), webauth_at);
    }
    
    
    /**
     * Turn the WEBAUTHS query param into a token.
     * @param   request The request to take the query string from.
     * @return  Will return a token.
     * @throws  ServletException    if the token is bad.
     */
    private Token webauthsToken(HttpServletRequest request) throws ServletException {
        String qs = request.getQueryString();
        int start = qs.indexOf("WEBAUTHS=") + "WEBAUTHS=".length();
        int end = qs.indexOf(";", start);
        Token t = decrypt(qs.substring(start, end), "app");
        return t;
    }

    
    /**
     * Turn the WEBAUTHR query param into a token.
     * @param   request     The request to take the query string from.
     * @param   sessionKey  The session key to decrypt the WEBAUTHR token with.
     * @return  Will return a token.
     * @throws  ServletException    if the token is bad.
     */
    private Token webauthrToken(HttpServletRequest request, SecretKey sessionKey) throws ServletException {
        try {
            String qs = request.getQueryString();
            int start = qs.indexOf("WEBAUTHR=") + "WEBAUTHR=".length();
            int end = qs.indexOf(";", start);
            Token t = new Token(base64decode(qs.substring(start, end)), sessionKey);
            return t;
        }
        catch(GeneralSecurityException gse) {
            throw new ServletException("Client "+rip+" sent an invalid WEBAUTHR token.", gse);
        }
    }

    
    /**
     * Redirect the client an extra time so that the WEBAUTH tokens are not
     * visible in the URL field of the browser.
     * @param   request     A wrapped request that will not return the WEBAUTH params.
     */
    private void extraRedirect(RequestWrapper request) throws ServletException {
        String queryString = "";
        if(request.getQueryString() != null) {
            queryString = "?"+request.getQueryString();
        }
        try { response.sendRedirect(request.getRequestURL()+queryString); }
        catch(IOException ioe) { throw new ServletException("Could not send the client an extra redirect.", ioe); }
        debug("-------- Sent an extra redirect to remove Webauth tokens from URL bar.");
    }

    
    /**
     * Try to grab an app token and get the username from there.
     * @param   privateKey  The most suitable key to decrypt the token with.
     */
    private void handleAppCookie(WebauthKey privateKey) throws ServletException {
        if(!cookies.containsKey("webauth_at")) { return; }
        Cookie webauth_at = cookies.get("webauth_at");
        Token app = null;
        try { app = decrypt(webauth_at.getValue(), "app"); }
        // if the user has a bad app cookie then return
        catch(ServletException se) { return; }
        if(logger.debug()) { debug(app.toString()); }
        username = app.getString("s");
        if(username == null || username.length() < 1) { return; }
        if(app.getBinary("lt") != null) {
            app.add("lt", Token.unixTimestampBytes(System.currentTimeMillis()));
            String encrypted = null;
            try { encrypted = app.encrypt(privateKey.key()); }
            catch(GeneralSecurityException gse) { throw new ServletException("Could not encrypt app-token.", gse); }
            webauth_at.setValue(encrypted);
            webauth_at.setSecure(true);
            webauth_at.setMaxAge(-1);
            webauth_at.setPath("/");
            response.addCookie(webauth_at);
            debug("Setting a new last-used time on app token cookie.");
        }
        debug("Found a valid app-token cookie.");
    }

    
    /** Convenience method. */
    public static byte[] base64decode(String data) throws ServletException {
        try { return Base64.decodeBase64(data.getBytes("US-ASCII")); }
        catch(UnsupportedEncodingException uee) {
            /* should never happen as US-ASCII must exist in a Java impl. */
            throw new ServletException(uee);
        }
    }
    
    
    /** Redirect a user to the Webauth login URL to be authenticated. */
    private void redirect() throws ServletException, IOException {
        StringBuilder url = new StringBuilder();
        url.append(request.getRequestURL());
        String queryString = request.getQueryString();
        if(queryString != null) { url.append("?").append(queryString); }
        
        Token token = new Token();
        token.add("t", "req");
        token.add("ct", Token.unixTimestampBytes(System.currentTimeMillis()));
        token.add("ru", url.toString());
        if(config.getInitParameter("ProxyCredentials") == null) {
            token.add("rtt", "id");
            if(config.getInitParameter("WebAuthSubjectAuthType") == null) { token.add("sa", "webkdc"); }
            else { token.add("sa", config.getInitParameter("WebAuthSubjectAuthType")); }
            debug("Redirecting to get an id token.");
        }
        else {
            token.add("rtt", "proxy");
            token.add("pt", "krb5");
            debug("Redirecting to get a proxy token.");
        }
        Token as = new Token();
        as.add("t", "app");
        as.add("et", Token.unixTimestampBytes(System.currentTimeMillis()+1800000L));    // 30 mins et
        as.add("k", sessionKey.getEncoded());
        try {
            // hacky hack hack to base64 decode it after encrypting it...
            token.add("as", base64decode(as.encrypt(privateKey.key())));
            String redirectUrl = webAuthLoginURL+"?RT="+token.encrypt(sessionKey)+";ST="+serviceToken;
            response.sendRedirect(redirectUrl);
            if(logger.debug()) { debug("-------- Redirected to URL: "+redirectUrl); }
        }
        catch(GeneralSecurityException gse) { throw new ServletException("Could not redirect user.", gse); }
    }
}