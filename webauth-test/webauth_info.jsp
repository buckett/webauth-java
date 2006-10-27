<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html  PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<!--
  $HeadURL$
  $LastChangedRevision$
  $LastChangedDate$
  $LastChangedBy$
-->

<%@ page import="javax.security.auth.login.*" %>

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head><title>WebAuth Java Test Page</title></head>
<body text="#ffffff" bgcolor="#000000">

<p><h1>WebAuth Java Test Page</h1></p>

<p><b>AuthType:</b> <%= request.getAuthType() %><br/>
<b>RemoteUser:</b> <%= request.getRemoteUser() %><br/>
<b>UserPrincipal:</b> <%= request.getUserPrincipal() %>
</p>

<p><b>JAAS</b><br/>
<%
try {
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
JAAS failure, got a LoginException.
<%
}
%>

</body>
</html>
