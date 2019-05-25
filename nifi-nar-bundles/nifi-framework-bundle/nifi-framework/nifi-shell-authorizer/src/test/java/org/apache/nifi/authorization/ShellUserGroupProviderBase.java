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

import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeFalse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


abstract class ShellUserGroupProviderBase {
    private static final Logger logger = LoggerFactory.getLogger(ShellUserGroupProviderBase.class);
    
    private final String KNOWN_USER  = "root";
    private final String KNOWN_UID   = "0";

    @SuppressWarnings("FieldCanBeLocal")
    private final String KNOWN_GROUP = "root";

    @SuppressWarnings("FieldCanBeLocal")
    private final String OTHER_GROUP = "wheel"; // e.g., macos
    private final String KNOWN_GID   = "0";

    protected boolean isWindowsEnvironment() {
        return System.getProperty("os.name").toLowerCase().startsWith("windows");
    }

    void testGetUsers(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        Set<User> users = provider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    void testGetUser(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        User root = provider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    void testGetUserByIdentity(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        User root = provider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    void testGetGroups(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        Set<Group> groups = provider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    void testGetGroup(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    void testGroupMembership(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);

        try {
            assertTrue(group.getUsers().size() > 0);
        } catch (final AssertionError ignored) {
            logger.warn("root group count zero on this system");
        }

        try {
            assertTrue(group.getUsers().contains(KNOWN_USER));            
        } catch (final AssertionError ignored) {
            logger.warn("root group membership unexpected on this system");
        }
    }

    void testGetUserAndGroups(UserGroupProvider provider) {
        assumeFalse(isWindowsEnvironment());

        UserAndGroups user = provider.getUserAndGroups(KNOWN_UID);
        assertNotNull(user);

        try {
            assertTrue(user.getGroups().size() > 0);
        } catch (final AssertionError ignored) {
            logger.warn("root user and groups group count zero on this system");
        }

        Set<Group> groups = provider.getGroups();
        assertTrue(groups.size() > user.getGroups().size());
    }
}
