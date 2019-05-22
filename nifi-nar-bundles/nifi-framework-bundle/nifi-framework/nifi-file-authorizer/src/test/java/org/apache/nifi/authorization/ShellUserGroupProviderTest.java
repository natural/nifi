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


abstract class ShellUserGroupProviderBase {
    private final String KNOWN_USER  = "root";
    private final String KNOWN_UID   = "0";

    private final String KNOWN_GROUP = "root";
    private final String OTHER_GROUP = "wheel"; // e.g., macos
    private final String KNOWN_GID   = "0";
    
    public void testGetUsers(UserGroupProvider provider) throws Exception {
        Set<User> users = provider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    public void testGetUser(UserGroupProvider provider) throws Exception {
        User root = provider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    } 
   
    public void testGetUserByIdentity(UserGroupProvider provider) throws Exception {
        User root = provider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    public void testGetGroups(UserGroupProvider provider) throws Exception {
        Set<Group> groups = provider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    public void testGetGroup(UserGroupProvider provider) throws Exception {
        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    public void testGroupMembership(UserGroupProvider provider) throws Exception {
        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getUsers().size() > 0);
        assertTrue(group.getUsers().contains(KNOWN_USER));
    }

    public void testGetUserAndGroups(UserGroupProvider provider) throws Exception {
        UserAndGroups user = provider.getUserAndGroups(KNOWN_UID);
        assertNotNull(user);
        assertTrue(user.getGroups().size() > 0);

        Set<Group> groups = provider.getGroups();
        assertTrue(groups.size() > user.getGroups().size());
    }
}


public class ShellUserGroupProviderTest extends ShellUserGroupProviderBase {
    public static final Logger logger = LoggerFactory.getLogger(ShellUserGroupProviderTest.class);
    
    public final static String ALPINE_IMAGE = "panubo/sshd:latest";
    public final static String CENTOS_IMAGE = "natural/centos-sshd:latest";
    public final static String DEBIAN_IMAGE = "natural/debian-sshd:latest";
    public final static String UBUNTU_IMAGE = "natural/ubuntu-sshd:latest";
    public final static List<String> TEST_CONTAINER_IMAGES = Arrays.asList(ALPINE_IMAGE
                                                                           , CENTOS_IMAGE
                                                                           , DEBIAN_IMAGE
                                                                           , UBUNTU_IMAGE);
    
    public final static String CONTAINER_SSH_AUTH_KEYS = "/root/.ssh/authorized_keys";
    public final static Integer CONTAINER_SSH_PORT = 22;
    
    private AuthorizerConfigurationContext authContext;
    private ClassLoader classLoader;
    private ShellUserGroupProvider localProvider;
    private String sshPrivKeyFile;
    private String sshPubKeyFile;
    private UserGroupProviderInitializationContext initContext;
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    
    @Before
    public void setup() throws IOException {
        classLoader = Thread.currentThread().getContextClassLoader();
        
        authContext = mock(AuthorizerConfigurationContext.class);
        initContext = mock(UserGroupProviderInitializationContext.class);

        localProvider = new ShellUserGroupProvider();
        localProvider.initialize(initContext);
        localProvider.onConfigured(authContext);
        
        sshPrivKeyFile = tempFolder.getRoot().getAbsolutePath() + "/id_rsa";
        sshPubKeyFile = sshPrivKeyFile + ".pub";
        localProvider.runShell("yes | ssh-keygen -C '' -N '' -t rsa -f " + sshPrivKeyFile);
        
        // Fix the file permissions to abide by the ssh client
        // requirements:
        Arrays.asList(sshPrivKeyFile, sshPubKeyFile).forEach(name -> {
                final File f = new File(name);
                assertTrue(f.setReadable(false, false));
                assertTrue(f.setReadable(true));
            });
    }

    @Test
    public void testGetUsers() throws Exception {
        testGetUsers(localProvider);
    }

    
    @Test
    public void testGetUser() throws Exception {
        testGetUser(localProvider);
    }
    
    @Test
    public void testGetUserByIdentity() throws Exception {
        testGetUserByIdentity(localProvider);
    }

    @Test
    public void testGetGroups() throws Exception {
        testGetGroups(localProvider);
    }
    
    @Test
    public void testGetGroup() throws Exception {
        testGetGroup(localProvider);
    }    

    @Test
    public void testGroupMembership() throws Exception {
        testGroupMembership(localProvider);
    }
        
    @Test
    public void testGetUserAndGroups() throws Exception {
        testGetUserAndGroups(localProvider);
    }
        
    public GenericContainer createContainer(String image) throws IOException, InterruptedException {
        GenericContainer container = new GenericContainer(image)
            .withEnv("SSH_ENABLE_ROOT", "true")
            .withExposedPorts(CONTAINER_SSH_PORT);
        container.start();
        
        // This should go into the docker image, but we don't
        // control the images much:
        container.execInContainer("mkdir", "-p", "/root/.ssh");
        container.copyFileToContainer(MountableFile.forHostPath(sshPubKeyFile),  CONTAINER_SSH_AUTH_KEYS);
        return container;
    }
    
    public UserGroupProvider createRemoteProvider(GenericContainer container) {
        final ShellCommandsProvider remoteCommands = RemoteShellCommands.wrapOtherProvider(new NssShellCommands(),
                                                                                           sshPrivKeyFile,
                                                                                           container.getContainerIpAddress(),
                                                                                           container.getMappedPort(CONTAINER_SSH_PORT)
                                                                                           );
            
        ShellUserGroupProvider remoteProvider = new ShellUserGroupProvider(); 
        remoteProvider.initialize(initContext);
        remoteProvider.onConfigured(authContext, remoteCommands);
        return remoteProvider;
    }
    
    @Test
    public void testVariousSystemImages() throws Exception {
        TEST_CONTAINER_IMAGES.forEach(image -> {
                GenericContainer container;

                logger.info("creating container from image: " + image);
                try {
                    container = createContainer(image);
                } catch (final Exception e) {
                    logger.error("create container exception: " + e);
                    return;
                }
                UserGroupProvider remoteProvider = createRemoteProvider(container);

                try {
                    testGetUsers(remoteProvider);
                    testGetUser(remoteProvider);
                    testGetGroups(remoteProvider);
                    testGetGroup(remoteProvider);
                    //testGroupMembership(remoteProvider);
                    //testGetUserAndGroups(remoteProvider);
                } catch (final Exception e) {
                    logger.error("Exception running remote provider on image: " + image +  ", exception: " + e);
                }
            
                container.stop();
                remoteProvider.preDestruction();
                logger.info("finished with container image: " + image);
            });
    }
}
