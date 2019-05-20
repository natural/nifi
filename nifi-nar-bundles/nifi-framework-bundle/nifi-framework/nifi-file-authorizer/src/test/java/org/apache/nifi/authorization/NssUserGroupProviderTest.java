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
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import static org.mockito.Mockito.mock;


public class NssUserGroupProviderTest {
    private NssUserGroupProvider nssProvider;
    private AuthorizerConfigurationContext authContext;
    private UserGroupProviderInitializationContext initContext;

    private final String KNOWN_USER = "root";
    private final String KNOWN_UID = "0";

    private final String KNOWN_GROUP = "root";
    private final String OTHER_GROUP = "wheel"; // on macos
    private final String KNOWN_GID = "0";

    @Before
    public void setup() throws IOException {
        authContext = mock(AuthorizerConfigurationContext.class);
        initContext = mock(UserGroupProviderInitializationContext.class);

        nssProvider = new NssUserGroupProvider();
        nssProvider.initialize(initContext);
        nssProvider.onConfigured(authContext);
    }

    @Test
    public void testGetUsers() throws Exception {
        Set<User> users = nssProvider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    @Test
    public void testGetUser() throws Exception {
        User root = nssProvider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testGetUserByIdentity() throws Exception {
        User root = nssProvider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testGetGroups() throws Exception {
        Set<Group> groups = nssProvider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    @Test
    public void testGetGroup() throws Exception {
        Group group = nssProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    @Test
    public void testGroupMembership() throws Exception {
        Group group = nssProvider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getUsers().size() > 0);
        assertTrue(group.getUsers().contains(KNOWN_USER));
    }

    @Test
    public void testGetUserAndGroups() throws Exception {
        UserAndGroups principal = nssProvider.getUserAndGroups(KNOWN_UID);
        assertNotNull(principal);
        assertTrue(principal.getGroups().size() > 0);

        Set<Group> groups = nssProvider.getGroups();
        assertTrue(groups.size() > principal.getGroups().size());
    }
}
