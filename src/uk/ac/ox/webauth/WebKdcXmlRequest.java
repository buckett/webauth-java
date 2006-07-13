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
import java.io.InputStream;
import java.io.IOException;
import javax.servlet.FilterConfig;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;


/**
 * Do a post to the WebKDC and return the response.
 *
 * <p/>$HeadURL$
 * <br/>$LastChangedRevision$
 * <br/>$LastChangedDate$
 * <br/>$LastChangedBy$
 * @author     Mats Henrikson
 * @version    $LastChangedRevision$
 */
public class WebKdcXmlRequest {
    
    
    /** The URL to post the message to. */
    private String url;
    
    
    /**
     * Initialise the request.
     * @param   url The URL to make the request to.
     */
    public WebKdcXmlRequest(String url) { this.url = url; }
    
    
    /**
     * Post the request and return the response document.
     * @param   body    The request body to post.
     * @return  the parsed XML response.
     * @throws  IOException when something goes wrong.
     */
    public Document doPost(String body) throws IOException {
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod(url);
        post.setRequestEntity(new StringRequestEntity(body, "text/xml", null));
        InputStream xml = null;
        Document doc = null;
        try {
            int rcode = client.executeMethod(post);
            xml = post.getResponseBodyAsStream();
            DocumentBuilder docBuilder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
            doc = docBuilder.parse(xml);
            
            if(rcode != 200) {
                throw new IOException("Got response "+rcode+" when trying to post to URL "+url+" with request body:\n"
                        +body);
            }
        }
        catch(ParserConfigurationException pce) {
            IOException ioe = new IOException("Could not create the XML parser to read the response.");
            ioe.initCause(pce);
            throw ioe;
        }
        catch(SAXException se) {
            IOException ioe = new IOException("Could not parse the XML response.");
            ioe.initCause(se);
            throw ioe;
        }
        finally {
            if(xml != null) { xml.close(); }
            post.releaseConnection();
        }
        return doc;
    }
}