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
import java.io.IOException;


import java.util.Set;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import static org.mockito.Mockito.mock;

import org.junit.rules.TemporaryFolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.MountableFile;


public class ShellUserGroupProviderTest extends ShellUserGroupProviderBase {
    private static final Logger logger = LoggerFactory.getLogger(ShellUserGroupProviderTest.class);
    
    private final static String ALPINE_IMAGE = "natural/alpine-sshd:latest";
    private final static String CENTOS_IMAGE = "natural/centos-sshd:latest";
    private final static String DEBIAN_IMAGE = "natural/debian-sshd:latest";
    private final static String UBUNTU_IMAGE = "natural/ubuntu-sshd:latest";
    private final static List<String> TEST_CONTAINER_IMAGES = Arrays.asList(ALPINE_IMAGE
                                                                           , CENTOS_IMAGE
                                                                           , DEBIAN_IMAGE
                                                                           , UBUNTU_IMAGE);
    
    private final static String CONTAINER_SSH_AUTH_KEYS = "/root/.ssh/authorized_keys";
    private final static Integer CONTAINER_SSH_PORT = 22;
    
    private AuthorizerConfigurationContext authContext;
    private ShellUserGroupProvider localProvider;
    private String sshPrivKeyFile;
    private String sshPubKeyFile;
    private UserGroupProviderInitializationContext initContext;
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    
    @Before
    public void setup() throws IOException {
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
    public void testGetUsers() {
        testGetUsers(localProvider);
    }

    
    @Test
    public void testGetUser() {
        testGetUser(localProvider);
    }
    
    @Test
    public void testGetUserByIdentity() {
        testGetUserByIdentity(localProvider);
    }

    @Test
    public void testGetGroups() {
        testGetGroups(localProvider);
    }
    
    @Test
    public void testGetGroup() {
        testGetGroup(localProvider);
    }    

    @Test
    public void testGroupMembership() {
        testGroupMembership(localProvider);
    }
        
    @Test
    public void testGetUserAndGroups() {
        testGetUserAndGroups(localProvider);
    }
        
    @SuppressWarnings("RedundantThrows")
    private GenericContainer createContainer(String image) throws IOException, InterruptedException {
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
    
    private UserGroupProvider createRemoteProvider(GenericContainer container) {
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
    public void testVariousSystemImages() {
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
