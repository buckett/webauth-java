<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html  PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<!--
  $HeadURL$
  $LastChangedRevision$
  $LastChangedDate$
  $LastChangedBy$
-->

<%@ page import="javax.security.auth.login.*,java.io.*" %>

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head><title>WebAuth Java Test Page</title></head>
<body text="#ffffff" bgcolor="#000000">

<p><h1>WebAuth Java Test Page</h1></p>

<p>
<b>Test pages:</b><br/>
<a href="../standard/">Standard</a><br/>
<a href="../nojaas/">No JAAS</a><br/>
<a href="../logout/">Logout</a><br/>
<a href="../proxy/">Proxy credentials (may not be configured)</a><br/>
</p>

<p><b>AuthType:</b> <%= request.getAuthType() %><br/>
<b>RemoteUser:</b> <%= request.getRemoteUser() %><br/>
<b>UserPrincipal:</b> <%= request.getUserPrincipal() %>
</p>

<p><b>JAAS</b><br/>
<%
try {
    /***************************************************************
     *                                                             *
     *  You must define the name of the JAAS login context below.  *
     *                                                             *
     ***************************************************************/
    LoginContext lc = new LoginContext("Webauth");
    lc.login();
%>
JAAS login successful.<br/>
<%
    lc.logout();
%>
JAAS logout successful.<br/>
<%
}

catch (LoginException le) {
%>
JAAS failure, got a LoginException.<br/>
Either JAAS is turned off <b>(which can be a normal occurrence)</b>, or JAAS is not
configured properly. If you are not going to use JAAS then it is safe to ignore
this.<br/>
<p>Common causes for this are:
<ul>
  <li>JAAS is turned off for this location in the WebAuth Java parameters.</li>
  <li>Specifying the incorrect JAAS context to use (remember that you must also
  put the name of the context in the source of this JSP page).</li>
  <li>Not configuring a JAAS context at all. How to do that is different for
  every container.</li>
</ul>
</p>

<p>The actual exception text is included as a comment in the source of this
page.</p>
<%
    out.println("<!--\n\n");
    StringWriter sw = new StringWriter();
    le.printStackTrace(new PrintWriter(sw));
    out.println(sw.toString());
    out.println("-->");
}

catch(SecurityException se) {
%>
JAAS failure, got a SecurityException.<br/>
This usually means that no JAAS config file was found <b>(which can be a normal
occurrence)</b>. If you are not going to use JAAS then it is safe to ignore
this.<br/>

<p>The actual exception text is included as a comment in the source of this
page.</p>
<%
    out.println("<!--\n\n");
    StringWriter sw = new StringWriter();
    se.printStackTrace(new PrintWriter(sw));
    out.println(sw.toString());
    out.println("-->");
}
%>

</body>
</html>
