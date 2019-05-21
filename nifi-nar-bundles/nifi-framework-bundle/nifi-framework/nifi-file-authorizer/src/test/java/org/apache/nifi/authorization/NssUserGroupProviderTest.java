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
package org.apache.nifi.authorization;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.io.InputStream;
import java.io.InputStreamReader;


import java.time.Duration;
import java.util.Set;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import static org.mockito.Mockito.mock;

import org.junit.rules.TemporaryFolder;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;


public class NssUserGroupProviderTest {
    private ClassLoader classLoader;
    
    private NssUserGroupProvider shellProvider;
    private NssUserGroupProvider remoteShellProvider;
    
    private AuthorizerConfigurationContext authContext;
    private UserGroupProviderInitializationContext initContext;

    private final String KNOWN_USER  = "root";
    private final String KNOWN_UID   = "0";

    private final String KNOWN_GROUP = "root";
    private final String OTHER_GROUP = "wheel"; // e.g., macos
    private final String KNOWN_GID   = "0";

    @Before
    public void setup() throws IOException {
        classLoader = Thread.currentThread().getContextClassLoader();
        
        authContext = mock(AuthorizerConfigurationContext.class);
        initContext = mock(UserGroupProviderInitializationContext.class);

        shellProvider = new NssUserGroupProvider();
        shellProvider.initialize(initContext);
        shellProvider.onConfigured(authContext);
        
        remoteShellProvider = new NssUserGroupProvider(); 
        // purposely not initialized
    }

    //@Ignore
    @Test
    public void testGetUsers() throws Exception {
        Set<User> users = shellProvider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    //@Ignore    
    @Test
    public void testGetUser() throws Exception {
        User root = shellProvider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    //@Ignore    
    @Test
    public void testGetUserByIdentity() throws Exception {
        User root = shellProvider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    //@Ignore    
    @Test
    public void testGetGroups() throws Exception {
        Set<Group> groups = shellProvider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    //@Ignore        
    @Test
    public void testGetGroup() throws Exception {
        Group group = shellProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    //@Ignore        
    @Test
    public void testGroupMembership() throws Exception {
        Group group = shellProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getUsers().size() > 0);
        assertTrue(group.getUsers().contains(KNOWN_USER));
    }

    //@Ignore        
    @Test
    public void testGetUserAndGroups() throws Exception {
        UserAndGroups principal = shellProvider.getUserAndGroups(KNOWN_UID);
        assertNotNull(principal);
        assertTrue(principal.getGroups().size() > 0);

        Set<Group> groups = shellProvider.getGroups();
        assertTrue(groups.size() > principal.getGroups().size());
    }
    
    public final static List<String> IMAGES = Arrays.asList("panubo/sshd:latest",
                                                            "natural/centos-sshd:latest",
                                                            "natural/debian-sshd:latest");
    
    public final static String SSH_KEY_PUB = "ssh-keys/test_id_rsa.pub";
    public final static String SSH_KEY_PRV = "ssh-keys/test_id_rsa";
    public final static String AUTH_KEYS_PATH = "/root/.ssh/authorized_keys";
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    @Test
    public void testCheckAlpineImage() throws Exception {
        // Carefully crafted command replacement string:
        final String remoteCommand = "ssh " +
            "-o 'StrictHostKeyChecking no' " + 
            "-o 'PasswordAuthentication no' " +
            "-o \"RemoteCommand %s\" " + 
            "-i %s -p %s -l root %s";

        // Copy the private key to the file system and set it readable
        // to us only, because the ssh client requires that:
        final File tempFile = tempFolder.newFile();
        assertTrue(tempFile.setReadable(false, false));
        assertTrue(tempFile.setReadable(true));
        
        try (final InputStream stream = classLoader.getResourceAsStream(SSH_KEY_PRV);
             final FileWriter writer = new FileWriter(tempFile);
             final InputStreamReader reader = new InputStreamReader(stream)) {
            
            char[] buffer = new char[8 * 1024];
            int bytesRead;
            while ((bytesRead = reader.read(buffer)) != -1) {
                writer.write(buffer, 0, bytesRead);
            }
        }

        // 
        final Map<NssUserGroupProvider.Command, String> nssCommands = shellProvider.getCommands();
        final String keyPath = tempFile.getAbsolutePath();        
        
        IMAGES.forEach(image -> {
                GenericContainer container = new GenericContainer(image)
                    .withEnv("SSH_ENABLE_ROOT", "true")
                    .withExposedPorts(22)
                    .withClasspathResourceMapping(SSH_KEY_PUB, AUTH_KEYS_PATH, BindMode.READ_WRITE);

                container.start();
                
            String containerIP = container.getContainerIpAddress();
            Integer containerPort = container.getMappedPort(22);
            Map<NssUserGroupProvider.Command, String> remoteCommands = new HashMap<>();
            
            for (NssUserGroupProvider.Command command : nssCommands.keySet()) {
                String commandLine = nssCommands.get(command);
                remoteCommands.put(command, String.format(remoteCommand, 
                                                          commandLine, 
                                                          keyPath, 
                                                          containerPort, 
                                                          containerIP));
            }
            remoteShellProvider.setCommands(remoteCommands);
            
            Set<User> users = remoteShellProvider.getUsers();
            assertNotNull(users);
            assertTrue(users.size() > 0);

            User root = remoteShellProvider.getUser(KNOWN_UID);
            assertNotNull(root);
            assertEquals(KNOWN_USER, root.getIdentity());
            assertEquals(KNOWN_UID, root.getIdentifier());
            
            container.stop();
            });
        
    }
}
