/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET requests.

   This file is also available at http://www.learnsecurity.com/ntk
 
***********************************************************************/

//package com.learnsecurity;

import java.io.*;
import java.net.*;
import java.util.*;

public class SimpleWebServer {
    private static final int PORT = 8080;
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "password";

    // The socket used to process incoming connections from web clients
    private static ServerSocket dServerSocket;

    public SimpleWebServer() throws Exception {
        dServerSocket = new ServerSocket(PORT);
    }

    public void run() throws Exception {
        while (true) {
            // wait for a connection from a client
            Socket s = dServerSocket.accept();

            Connection request = new Connection(s);
            request.start(); 
        }
    }

    class Connection extends Thread {
    Socket clientSocket;

    public Connection() {
        super();
    }
    Connection(Socket s) {
        super();
        clientSocket = s;
    }

    // Reads the HTTP request from the client, and responds with the file the user requested or a HTTP error code.
    public void run() {
        try {
            // used to read data from the client
            BufferedReader br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            // used to write data to the client
            OutputStreamWriter osw = new OutputStreamWriter(clientSocket.getOutputStream());

            // read the HTTP request from the client
            String request = br.readLine();
            logEntry("log.txt", request + "\n");

            if (request == null)
                return;

            String command = null;
            String pathname = null;

            // parse the HTTP request
            StringTokenizer st = new StringTokenizer(request, " ");

            command = st.nextToken();
            pathname = st.nextToken();

            if(!authenticate(br)) {
                osw.write("HTTP/1.0 401 Unauthorized\r\n");
                osw.write("WWW-Authenticate: Basic realm=\"SimpleWebServer\"\r\n");
                osw.write("Content-Type: text/html\r\n");
                osw.write("\r\n");
                osw.write("<HTML><HEAD><TITLE>401 Unauthorized</TITLE></HEAD>\r\n");
                osw.write("<BODY><H1>401 Unauthorized</H1>\r\n");
                osw.write("<P>You must enter a valid user name and password to access this resource.</P>\r\n");
                osw.write("</BODY></HTML>\r\n");
                osw.flush();
                osw.close();
                return;
            }

            System.out.println("Authenticated");

            if (command.equals("GET")) {
                System.out.println("GET request for " + pathname);
                logEntry("log.txt", "GET request for " + pathname);
                serveFile(osw, pathname);
            } else if (command.equals("POST")) {
                System.out.println("POST request for " + pathname);
                logEntry("log.txt", "POST request for " + pathname);
                storeFile(br, osw, pathname);
            } else {
                osw.write("HTTP/1.0 501 Not Implemented\n\n");
            }

            // close the connection to the client
            osw.close();
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
    }

    public boolean authenticate(BufferedReader br) throws Exception {
        String s = "";
        String encoded = "";
        String decoded = "";
        String user = "";
        String pass = "";

        while (br.ready()) {
            s = br.readLine();
            System.out.println(s);
            if(s.contains("Basic")) {
                encoded = s.substring(s.indexOf("Basic") + 6);
                break;
            }
            if(s.equals("")) return false;
        }

        decoded = new String(Base64.getDecoder().decode(encoded));
        user = decoded.substring(0, decoded.indexOf(":"));
        pass = decoded.substring(decoded.indexOf(":") + 1);

        if(user.equals(USERNAME) && pass.equals(PASSWORD)) {
            return true;
        }
        return false;
    }

    public void serveFile(OutputStreamWriter osw, String pathname) throws Exception {
        final int MAX_DOWNLOAD_LIMIT = 1048576;
        FileReader fr = null;
        int c = -1;
        int sentBytes = 0;

        System.out.println("Serving file " + pathname);

        // remove the initial slash at the beginning of the pathname in the request
        if (pathname.charAt(0) == '/')
            pathname = pathname.substring(1);

        // if there was no filename specified by the client, serve the "index.html" file
        if (pathname.equals(""))
            pathname = "index.html";

        // try to open file specified by pathname
        try {
            fr = new FileReader(pathname);
            c = fr.read();
        } catch (Exception e) {
            // if the file is not found,return the appropriate HTTP response code
            System.out.println("File not found: " + pathname);
            osw.write("HTTP/1.0 404 Not Found\n\n");
            return;
        }

        // if the requested file can be successfully opened and read
        // then return an OK response code and send the contents of the file
        osw.write ("HTTP/1.0 200 OK\n\n");
        while (c != -1) {
            if (sentBytes >= MAX_DOWNLOAD_LIMIT) {
                osw.write ("HTTP/1.0 403 Forbidden\n\n");
                logEntry("error_log.txt", pathname + " hit download limit");
                return;
            }
            osw.write (c);
            sentBytes++;
            c = fr.read();
        }
        logEntry("log.txt", pathname + " served");
    }

    public void storeFile(BufferedReader br, OutputStreamWriter osw,
                        String pathname) throws Exception {
        FileWriter fw = null;

        if (pathname.charAt(0) == '/')
            pathname = pathname.substring(1);

        try {
            fw = new FileWriter (pathname);
            String s = "-";
            boolean print = false;

            while (br.ready()) {
                s = br.readLine();
                if(s.equals("")) {
                    print = true;
                    continue;
                }
                System.out.println(s);
                if(print) fw.write(s + "\n");
            }

            fw.close();
            osw.write("HTTP/1.0 201 Created\n\n");
            logEntry("log.txt", pathname + " created");
        }
        catch (Exception e) {
        osw.write("HTTP/1.0 500 Internal Server Error\n\n");
        }
    }

    public void logEntry(String filename, String record) throws Exception {
        FileWriter fw = new FileWriter(filename, true);
        fw.write(getTimestamp() + " " + record);
        fw.close();
    }

    public String getTimestamp() {
        return (new Date()).toString();
    }
    }

    public static void main(String argv[]) throws Exception {

        /* Create a SimpleWebServer object, and run it */
        SimpleWebServer sws = new SimpleWebServer();
        sws.run();
    }
}