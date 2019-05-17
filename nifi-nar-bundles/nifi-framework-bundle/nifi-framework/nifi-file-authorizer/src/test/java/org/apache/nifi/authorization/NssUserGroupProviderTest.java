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

import org.apache.nifi.attribute.expression.language.StandardPropertyValue;
import org.apache.nifi.authorization.AuthorizerConfigurationContext;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.components.PropertyValue;
import org.apache.nifi.util.NiFiProperties;
import org.apache.nifi.util.file.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class NssUserGroupProviderTest {
    private NssUserGroupProvider nssProvider;
    private File primaryTenants;
    private File restoreTenants;
    private AuthorizerConfigurationContext authContext;
    private UserGroupProviderInitializationContext initContext;


    private final String KNOWN_USER = "root";
    private final String KNOWN_UID = "0";

    private final String KNOWN_GROUP = "root";
    private final String KNOWN_GROUP_ALT = "wheel"; // on macos
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
    public void testNssUsers() throws Exception {
        Set<User> users = nssProvider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    @Test
    public void testNssUserByIdentifier() throws Exception {
        User root = nssProvider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testNssUserByIdentity() throws Exception {
        User root = nssProvider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    @Test
    public void testNssGroups() throws Exception {
        Set<Group> groups = nssProvider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);

        Group root = nssProvider.getGroup(KNOWN_GID);
        assertNotNull(root);
        assertTrue(root.getName().equals(KNOWN_GROUP) || root.getName().equals(KNOWN_GROUP_ALT));
        assertEquals(KNOWN_GID, root.getIdentifier());

        // bin = nssProvider.getGroups();

        // when(configurationContext.getProperty(eq(FileAuthorizer.PROP_LEGACY_AUTHORIZED_USERS_FILE)))
        //         .thenReturn(new StandardPropertyValue("src/test/resources/authorized-users.xml", null));

        // writeFile(primaryTenants, EMPTY_TENANTS_CONCISE);
        // nssProvider.onConfigured(configurationContext);

        // // verify all users got created correctly
        // final Set<User> users = nssProvider.getUsers();
        // assertEquals(6, users.size());

        // final User user1 = nssProvider.getUserByIdentity("user1");
        // assertNotNull(user1);

        // final User user2 = nssProvider.getUserByIdentity("user2");
        // assertNotNull(user2);

        // final User user3 = nssProvider.getUserByIdentity("user3");
        // assertNotNull(user3);

        // final User user4 = nssProvider.getUserByIdentity("user4");
        // assertNotNull(user4);

        // final User user5 = nssProvider.getUserByIdentity("user5");
        // assertNotNull(user5);

        // final User user6 = nssProvider.getUserByIdentity("user6");
        // assertNotNull(user6);

        // // verify one group got created
        // final Set<Group> groups = nssProvider.getGroups();
        // assertEquals(1, groups.size());
        // final Group group1 = groups.iterator().next();
        // assertEquals("group1", group1.getName());
    }
}
