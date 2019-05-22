package org.apache.nifi.authorization;

import java.util.Set;

import static org.junit.Assert.*;

abstract class ShellUserGroupProviderBase {
    private final String KNOWN_USER  = "root";
    private final String KNOWN_UID   = "0";

    @SuppressWarnings("FieldCanBeLocal")
    private final String KNOWN_GROUP = "root";
    @SuppressWarnings("FieldCanBeLocal")
    private final String OTHER_GROUP = "wheel"; // e.g., macos
    private final String KNOWN_GID   = "0";

    void testGetUsers(UserGroupProvider provider) {
        Set<User> users = provider.getUsers();
        assertNotNull(users);
        assertTrue(users.size() > 0);
    }

    void testGetUser(UserGroupProvider provider) {
        User root = provider.getUser(KNOWN_UID);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    void testGetUserByIdentity(UserGroupProvider provider) {
        User root = provider.getUserByIdentity(KNOWN_USER);
        assertNotNull(root);
        assertEquals(KNOWN_USER, root.getIdentity());
        assertEquals(KNOWN_UID, root.getIdentifier());
    }

    void testGetGroups(UserGroupProvider provider) {
        Set<Group> groups = provider.getGroups();
        assertNotNull(groups);
        assertTrue(groups.size() > 0);
    }

    void testGetGroup(UserGroupProvider provider) {
        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getName().equals(KNOWN_GROUP) || group.getName().equals(OTHER_GROUP));
        assertEquals(KNOWN_GID, group.getIdentifier());
    }

    void testGroupMembership(UserGroupProvider provider) {
        Group group = provider.getGroup(KNOWN_GID);
        assertNotNull(group);
        assertTrue(group.getUsers().size() > 0);
        assertTrue(group.getUsers().contains(KNOWN_USER));
    }

    void testGetUserAndGroups(UserGroupProvider provider) {
        UserAndGroups user = provider.getUserAndGroups(KNOWN_UID);
        assertNotNull(user);
        assertTrue(user.getGroups().size() > 0);

        Set<Group> groups = provider.getGroups();
        assertTrue(groups.size() > user.getGroups().size());
    }
}
