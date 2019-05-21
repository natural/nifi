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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;


public class NssUserGroupProviderTest {
    public static final Logger logger = LoggerFactory.getLogger(NssUserGroupProviderTest.class);
    
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

    @Test
    public void testGetUsers() throws Exception {
        Set<User> users = shellProvider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    @Test
    public void testGetUser() throws Exception {
        User root = shellProvider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testGetUserByIdentity() throws Exception {
        User root = shellProvider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testGetGroups() throws Exception {
        Set<Group> groups = shellProvider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    @Test
    public void testGetGroup() throws Exception {
        Group group = shellProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    @Test
    public void testGroupMembership() throws Exception {
        Group group = shellProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getUsers().size() > 0);
        assertTrue(group.getUsers().contains(KNOWN_USER));
    }

    @Test
    public void testGetUserAndGroups() throws Exception {
        UserAndGroups principal = shellProvider.getUserAndGroups(KNOWN_UID);
        assertNotNull(principal);
        assertTrue(principal.getGroups().size() > 0);

        Set<Group> groups = shellProvider.getGroups();
        assertTrue(groups.size() > principal.getGroups().size());
    }
    
    public final static List<String> imageNames = Arrays.asList("panubo/sshd:latest",
                                                                "natural/centos-sshd:latest",
                                                                "natural/debian-sshd:latest",
                                                                "natural/ubuntu-sshd:latest"
                                                                );
    public final static String CONTAINER_SSH_AUTH_KEYS = "/root/.ssh/authorized_keys";
    public final static Integer CONTAINER_SSH_PORT = 22;

    // Carefully crafted command replacement string:
    public final static String remoteCommand = "ssh " +
        "-o 'StrictHostKeyChecking no' " + 
        "-o 'PasswordAuthentication no' " +
        "-o \"RemoteCommand %s\" " + 
        "-i %s -p %s -l root %s";
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    @Test
    public void testCheckAlpineImage() throws Exception {
        final String randoSshPrivKeyFile = tempFolder.getRoot().getAbsolutePath() + "/id_rsa";
        final String randoSshPubKeyFile = randoSshPrivKeyFile + ".pub";

        shellProvider.runShell("yes | ssh-keygen -C '' -N '' -t rsa -f " + randoSshPrivKeyFile);
        
        Arrays.asList(randoSshPrivKeyFile, randoSshPubKeyFile).forEach(name -> {
                final File f = new File(name);
                assertTrue(f.setReadable(false, false));
                assertTrue(f.setReadable(true));
            });
        
        final Map<NssUserGroupProvider.Command, String> nssCommands = shellProvider.getCommands();

        imageNames.forEach(image -> {
                GenericContainer container = new GenericContainer(image)
                    .withEnv("SSH_ENABLE_ROOT", "true")
                    .withExposedPorts(CONTAINER_SSH_PORT);
            container.start();
            try {
                container.execInContainer("mkdir", "-p", "/root/.ssh");
            }
            catch (final Exception e) {
                logger.error("error: " + e);
                return;
            }
            container.copyFileToContainer(MountableFile.forHostPath(randoSshPubKeyFile),  CONTAINER_SSH_AUTH_KEYS);
            String containerIP = container.getContainerIpAddress();
            Integer containerPort = container.getMappedPort(CONTAINER_SSH_PORT);
            Map<NssUserGroupProvider.Command, String> remoteCommands = new HashMap<>();
            
            for (NssUserGroupProvider.Command command : nssCommands.keySet()) {
                String commandLine = nssCommands.get(command);
                remoteCommands.put(command, String.format(remoteCommand, 
                                                          commandLine, 
                                                          randoSshPrivKeyFile,
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
