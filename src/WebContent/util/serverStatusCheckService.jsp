<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<%@page import="com.ibm.security.appscan.altoromutual.util.ServletUtil" errorPage="notfound.jsp"%>

{
	"HostName": "<%=ServletUtil.sanitizeWeb(request.getParameter("HostName"))%>",
	"HostStatus": "OK"
}