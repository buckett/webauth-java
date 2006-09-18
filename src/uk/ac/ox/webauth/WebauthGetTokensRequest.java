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
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.Subject;
import org.apache.commons.codec.binary.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ac.ox.webauth.asn1.KrbApReq;

/**
 * Post and parse the response of a &lt;getTokensRequest&gt; message to the
 * WebKDC to get initial credentials.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class WebauthGetTokensRequest {
    
    
    /** The first part of the xml message to send. */
    private static final String pre = "<getTokensRequest><requesterCredential type='krb5'>";
    /** The second part of the xml message to send. */
    private static final String post =
            "</requesterCredential><tokens><token type='service'/></tokens></getTokensRequest>";
        
    /** The URL to post the message to. */
    private String url;
    /** The KRB_AP_REQ bytes to authenticate with. */
    private byte[] krb_ap_req;
    
    /** The tokenData string. */
    public String tokenData() { return tokenData; }
    private String tokenData;
    /** The sessionKey string. */
    public String sessionKey() { return sessionKey; }
    private String sessionKey;
    /** The time the session key expires. */
    public String expires() { return expires; }
    private String expires;


    /**
     * Simple test method that tries to post the request to the WebKDC and parse
     * the response message.
     * @param   args    First principal and then the keytab to load a key from,
     *          then the service to generate the KRB_AP_REQ message for,
     *          then the url to post the request to.
     * @throws  Exception   when something goes wrong.
     */
    public static void main(String[] args) throws Exception {
        // get some keys to decrypt with
        long start = System.currentTimeMillis();
        KeytabKeyLoader kkl = new KeytabKeyLoader(args[0], args[1]);
        Subject sub = kkl.acquire();
        long stop = System.currentTimeMillis();
        System.out.println("Grabbing private key took "+(stop-start)+" milliseconds.");
        
        // grab the service ticket
        start = System.currentTimeMillis();
        try { Subject.doAs(sub, new ServiceTicketGrabberHack(args[0], args[2])); }
        catch(Exception e) { e.printStackTrace(); }
        KerberosTicket ticket = null;
        for(KerberosTicket t : sub.getPrivateCredentials(KerberosTicket.class)) {
            if(t.getServer().getName().startsWith(args[2])) {
                ticket = t;
            }
        }
        stop = System.currentTimeMillis();
        System.out.println("Getting the service ticket took "+(stop-start)+" milliseconds.");
        
        // request a webkdc token
        start = System.currentTimeMillis();
        byte[] krb_ap_req = new KrbApReq(ticket).toASN1Object().getEncoded();
        WebauthGetTokensRequest wgtr = new WebauthGetTokensRequest(args[3], krb_ap_req);
        wgtr.tokenRequest();
        stop = System.currentTimeMillis();
        System.out.println("Getting the WebKDC token took "+(stop-start)+" milliseconds.");
        System.out.println("Token data: "+wgtr.tokenData());
        System.out.println("Session key: "+wgtr.sessionKey());
        System.out.println("Expires: "+wgtr.expires());
        System.out.println("Success.");
    }
    
    
    /**
     * Simple constructor.
     * @param   url         The URL to post the request to.
     * @param   krb_ap_req  The KRB_AP_REQ bytes to authenticate with.
     */
    public WebauthGetTokensRequest(String url, byte[] krb_ap_req) {
        this.url = url;
        this.krb_ap_req = krb_ap_req;
    }
    
    
    /** Post a token request message to the WebKDC and parse the response. */
    public void tokenRequest() throws IOException {
        String request = getRequestMessage(krb_ap_req);
        WebKdcXmlRequest wkxr = new WebKdcXmlRequest(url);
        Document doc = wkxr.doPost(request);
        
        /* check if we actually got an error response and if so throw an exception
        <errorResponse>
          <!-- only if present in request -->
          <messageId>{message-id}</messageId>
          <errorCode>{numeric}<errorCode>
          <errorMessage>{message}<errorMessage>
        </errorResponse>
        */
        if("errorResponse".equalsIgnoreCase(doc.getFirstChild().getNodeName())) {
            NodeList children = doc.getFirstChild().getChildNodes();
            String errorCode = null;
            String errorMessage = null;
            for(int i = 0; i < children.getLength(); i++) {
                Node n = children.item(i);
                String nodeName = n.getNodeName();
                if("errorCode".equalsIgnoreCase(nodeName)) {
                    errorCode = n.getFirstChild().getNodeValue();
                }
                else if("errorMessage".equalsIgnoreCase(nodeName)) {
                    errorMessage = n.getFirstChild().getNodeValue();
                }
            }
            throw new IOException("Received error message when trying to request service token. Error code: '"
                    +errorCode+"', error message: '"+errorMessage+"'");
        }
        
        parseResponse(doc);
    }
    
    
    /**
     * Generate a request message.
     * @param   krb_ap_req  The KRB_AP_REQ bytes to use when generating the
     *          request message.
     * @return  The message to send to the WebKDC, fully encoded and ready to send.
     */
    private static String getRequestMessage(byte[] krb_ap_req) {
        return new StringBuilder()
                .append(pre)
                .append(new String(Base64.encodeBase64(krb_ap_req)))
                .append(post)
                .toString();
    }
    
    
    /**
     * Parse the response from the token request.
     * @param   doc The response document.
     * @throws  ParserConfigurationException if there is a problem with the parser.
     * @throws  SAXException if there are problems with the XML.
     */
    private void parseResponse(Document doc) throws IOException {
        /*
        <getTokensResponse>
          <tokens>
            <token id="{id-from-request}">
              <tokenData>{base64}</tokenData>
              <sessionKey>{base64-session-key}</sessionKey>
              <expires>{expiration-time}</expires>
            </token>
          </tokens>
        </getTokensResponse>
        */
        Node nToken = doc.getDocumentElement().getFirstChild().getFirstChild();
        if(!"token".equals(nToken.getNodeName())) {
            throw new IOException("XML response is not in expected format, element name is '"
                +nToken.getNodeName()+"', was expecting 'token'.");
        }
        NodeList children = nToken.getChildNodes();
        boolean data = false;
        boolean key = false;
        boolean time = false;
        for(int i = 0; i < children.getLength(); i++) {
            Node n = children.item(i);
            String name = n.getNodeName();
            if("tokenData".equals(name)) {
                tokenData = n.getFirstChild().getNodeValue();
                if(tokenData == null || tokenData.length() == 0) {
                    throw new IOException("XML response is not in expected format (tokenData element).");
                }
                data = true;
            }
            else if("sessionKey".equals(name)) {
                sessionKey = n.getFirstChild().getNodeValue();
                if(sessionKey == null || sessionKey.length() == 0) {
                    throw new IOException("XML response is not in expected format (sessionKey element).");
                }
                key = true;
            }
            else if("expires".equals(name)) {
                expires = n.getFirstChild().getNodeValue();
                if(expires == null || expires.length() == 0) {
                    throw new IOException("XML response is not in expected format (expires element).");
                }
                time = true;
            }
        }
        if(!(data && key && time)) {
            throw new IOException("Did not receive all expected XML elements in response. (tokenData:"
                    +data+", sessionkey:"+key+", expires:"+time+").");
        }
    }
}