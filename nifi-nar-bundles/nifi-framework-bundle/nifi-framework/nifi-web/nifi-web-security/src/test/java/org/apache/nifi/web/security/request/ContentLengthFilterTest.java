/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.nifi.web.security.request;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;

import org.eclipse.jetty.servlet.ServletHolder;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

import javax.servlet.DispatcherType;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;


/**
 * This test exercises the {@link ContentLengthFilter} class.
 *
 * The approach here is to use a {@link LocalConnector} and raw strings for HTTP requests.  The additional complexity
 * of a complete HTTP client isn't required to determine the behavior, and any client would introduce a new dependency.
 *
 */
public class ContentLengthFilterTest {
    private static final int MAX_CONTENT_LENGTH = 1000;
    private static final int SERVER_IDLE_TIMEOUT = 2500; // only one request needed + value large enough for slow systems
    private static final String POST_REQUEST = "POST / HTTP/1.1\r\nContent-Length: %d\r\nHost: h\r\n\r\n%s";
    private static final String FORM_REQUEST = "POST / HTTP/1.1\r\nContent-Length: %d\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n%s";
    public static final int FORM_CONTENT_SIZE = 128;

    private Server serverUnderTest;
    private LocalConnector localConnector;
    private ServletContextHandler contextUnderTest;

    @After
    public void stopServer() throws Exception {
        if (serverUnderTest != null && serverUnderTest.isRunning()) {
            serverUnderTest.stop();
        }
    }


    @Test
    public void testRequestsWithMissingContentLengthHeader() throws Exception {
        configureAndStartServer(readFullyAndRespondOK, -1);

        // This shows that the ContentLengthFilter rejects a request that does not have a content-length header.
        String response = localConnector.getResponse("POST / HTTP/1.0\r\n\r\n");
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "411 Length Required"));
    }


    @Test
    public void testRequestsWithContentLengthHeader() throws Exception {
        configureAndStartServer(readFullyAndRespondOK, -1);

        int smallClaim = 150;
        int largeClaim = 2000;

        String incompletePayload = StringUtils.repeat("1", 10);
        String largePayload = StringUtils.repeat("1", largeClaim + 200);

        // This shows that the ContentLengthFilter rejects a request when the client claims more than the max + sends more than the max:
        String response = localConnector.getResponse(String.format(POST_REQUEST, largeClaim, largePayload));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "413 Payload Too Large"));

        // This shows that the ContentLengthFilter rejects a request when the client claims more than the max + sends less the max:
        response = localConnector.getResponse(String.format(POST_REQUEST, largeClaim, incompletePayload));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "413 Payload Too Large"));

        // This shows that the ContentLengthFilter allows a request when it claims less than the max + sends more than the max:
        response = localConnector.getResponse(String.format(POST_REQUEST, smallClaim, largePayload));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "200 OK"));

        // This shows that the server times out when the client claims less than the max + sends less than the max + sends less than it claims to send:
        response = localConnector.getResponse(String.format(POST_REQUEST, smallClaim, incompletePayload), 500, TimeUnit.MILLISECONDS);
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "500 Server Error"));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "Timeout"));
    }


    @Test
    public void testJettyMaxFormSize() throws Exception {
        // This shows that the jetty server option for 'maxFormContentSize' is insufficient for our needs because it
        // catches requests like this:
        configureAndStartServer(readFormAttempt, FORM_CONTENT_SIZE);
        String form = "a=" + StringUtils.repeat("1", FORM_CONTENT_SIZE);
        String response = localConnector.getResponse(String.format(FORM_REQUEST, form.length(), form));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "413 Payload Too Large"));


        // But it does not catch requests like this:
        response = localConnector.getResponse(String.format(POST_REQUEST, form.length(), form+form));
        Assert.assertTrue(StringUtils.containsIgnoreCase(response, "417 Read Too Many Bytes"));
    }



    private HttpServlet readFullyAndRespondOK = new HttpServlet() {
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            ServletInputStream input = req.getInputStream();
            while (!input.isFinished()) {
                input.read();
            }
            resp.setStatus(HttpServletResponse.SC_OK);
        }
    };


    private HttpServlet readFormAttempt = new HttpServlet() {
        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
            try {
                req.getParameterMap();
                ServletInputStream input = req.getInputStream();
                int count = 0;
                while (!input.isFinished()) {
                    input.read();
                    count += 1;
                }
                if (count > FORM_CONTENT_SIZE + "a=\n".length()) {
                    resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Should not reach this code.");
                } else {
                    resp.sendError(HttpServletResponse.SC_EXPECTATION_FAILED, "Read Too Many Bytes");
                }

            } catch (final Exception e) {
                // This is the jetty context returning a 400 from the maxFormContentSize setting:
                if (StringUtils.containsIgnoreCase(e.getCause().toString(), "Form Too Large")) {
                    resp.sendError(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE, "Payload Too Large");
                } else {
                    resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Should not reach this code, either.");
                }
            }
        }
    };


    private void configureAndStartServer(HttpServlet servlet, int maxFormContentSize) throws Exception {
        serverUnderTest = new Server();
        localConnector = new LocalConnector(serverUnderTest);
        localConnector.setIdleTimeout(SERVER_IDLE_TIMEOUT);
        serverUnderTest.addConnector(localConnector);

        contextUnderTest = new ServletContextHandler(serverUnderTest, "/");
        if (maxFormContentSize > 0) {
            contextUnderTest.setMaxFormContentSize(maxFormContentSize);
        }
        contextUnderTest.addServlet(new ServletHolder(servlet), "/*");

        if (maxFormContentSize < 0) {
            FilterHolder holder = contextUnderTest.addFilter(ContentLengthFilter.class, "/*", EnumSet.of(DispatcherType.REQUEST));
            holder.setInitParameter(ContentLengthFilter.MAX_LENGTH_INIT_PARAM, String.valueOf(MAX_CONTENT_LENGTH));
        }
        serverUnderTest.start();
    }
}