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

import com.google.common.collect.ImmutableMap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;

import java.lang.InterruptedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/*
 * ShellUserGroupProvider implements UserGroupProvider by way of bash commands.
 */
public class NssUserGroupProvider implements UserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(NssUserGroupProvider.class);

    protected enum Command {
        USERS_LIST,    // list all users in the format "user1:uid1\nuser2:uid2"
        USER_GROUPS,   // list group membership if the format "group1,group2,groupN"

        GROUPS_LIST,   // list all groups in the format "group1:gid1\ngroup2:gid2"
        GROUP_MEMBERS, // list group members in the format "user1,user2,userN"

        SYS_CHECK      // shell command to determine system suitability
    }

    // This command set is selected for Linux hosts.  Its commands use
    // `getent`, which is part of the unix "Name Service Switch"
    // facility on Linux.
    private final static Map<Command, String> nssCommands = ImmutableMap.of(
            Command.USERS_LIST,    "getent passwd   | cut -f 1,3 -d ':'",
            Command.USER_GROUPS,   "id -nG %s | sed s/\\ /,/g",

            Command.GROUPS_LIST,   "getent group    | cut -f 1,3 -d ':'",
            Command.GROUP_MEMBERS, "getent group %s | cut -f 4   -d ':'",

            Command.SYS_CHECK,     "which getent"
    );

    // This command set is selected for Mac OS X hosts.  Its commands
    // use `dscl` and `awk`.
    private final static Map<Command, String> dsclCommands = ImmutableMap.of(
            Command.USERS_LIST,    "dscl . -list /Users  UniqueID | grep -v '^_' | sed 's/ \\{1,\\}/:/g'",
            Command.USER_GROUPS,   "id -nG %s | sed 's/\\ /,/g'",

            Command.GROUPS_LIST,   "dscl . -list /Groups    PrimaryGroupID  | grep -v '^_'     | sed 's/ \\{1,\\}/:/g'",
            Command.GROUP_MEMBERS, "dscl . -read /Groups/%s GroupMembership | cut -f 2- -d ' ' | sed 's/\\ /,/g'",

            Command.SYS_CHECK,     "which dscl"
    );

    private final static String OS_TYPE_ERROR = "Unsupported operating system.";
    private final static String SYS_CHECK_ERROR = "System check failed - cannot provide users and groups.";

    // id == identifier
    // name == identity
    private final Map<String, User> usersById = new HashMap<>();
    private final Map<String, User> usersByName = new HashMap<>();
    private final Map<String, Group> groupsById = new HashMap<>();

    // Our scheduler has one thread for users, one for groups:
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);

    // Our shell timeout, in seconds:
    private int shellTimeout = 10;

    // Commands selected during initialization:
    protected Map<Command, String> runtimeCommands;


    // Start of the UserGroupProvider implementation.  Docstrings
    // copied from the interface definition for reference.

    /**
     * Retrieves all users. Must be non null
     *
     * @return a list of users
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
        synchronized (usersById) {
            logger.info("getUsers has user set of size: " + usersById.size());
            return new HashSet<User>(usersById.values());
        }
    }

    /**
     * Retrieves the user with the given identifier.
     *
     * @param identifier the id of the user to retrieve
     * @return the user with the given id, or null if no matching user was found
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public User getUser(String identifier) throws AuthorizationAccessException {
        synchronized (usersById) {
            User user = usersById.get(identifier);
            logger.info("getUser has user: " + user);
            return user;
        }
    }

    /**
     * Retrieves the user with the given identity.
     *
     * @param identity the identity of the user to retrieve
     * @return the user with the given identity, or null if no matching user was found
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public User getUserByIdentity(String identity) throws AuthorizationAccessException {
        synchronized (usersByName) {
            User user = usersByName.get(identity);
            logger.info("getUserByIdentity has user: " + user);
            return user;
        }
    }

    /**
     * Retrieves all groups. Must be non null
     *
     * @return a list of groups
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public Set<Group> getGroups() throws AuthorizationAccessException {
        synchronized (groupsById) {
            logger.info("getGroups has group set of size: " + groupsById.size());
            return new HashSet<Group>(groupsById.values());
        }
    }

    /**
     * Retrieves a Group by id.
     *
     * @param identifier the identifier of the Group to retrieve
     * @return the Group with the given identifier, or null if no matching group was found
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public Group getGroup(String identifier) throws AuthorizationAccessException {
        synchronized (groupsById) {
            Group group = groupsById.get(identifier);
            logger.info("getGroup has group: " + group);
            return group;
        }
    }

    /**
     * Gets a user and their groups. Must be non null. If the user is not known the UserAndGroups.getUser() and
     * UserAndGroups.getGroups() should return null
     *
     * @return the UserAndGroups for the specified identity
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public UserAndGroups getUserAndGroups(String identity) throws AuthorizationAccessException {
        User user = getUser(identity);
        Set<Group> groups = new HashSet<>();

        for (Group g: getGroups()) {
            if (g.getUsers().contains(user.getIdentity())) {
                groups.add(g);
            }
        }

        return new UserAndGroups() {
            @Override
            public User getUser() {
                return user;
            }

            @Override
            public Set<Group> getGroups() {
                return groups;
            }
        };
    }

    /**
     * Called immediately after instance creation for implementers to perform additional setup
     *
     * @param initializationContext in which to initialize
     */
    @Override
    public void initialize(UserGroupProviderInitializationContext initializationContext) throws AuthorizerCreationException {
    }

    /**
     * Called to configure the Authorizer.
     *
     * @param configurationContext at the time of configuration
     * @throws AuthorizerCreationException for any issues configuring the provider
     */
    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
        // Our first init step is to select the command set based on the
        // operating system name:
        final String hostType = System.getProperty("os.name");

        if (hostType.startsWith("Linux")) {
            runtimeCommands = nssCommands;
        } else if (hostType.startsWith("Mac OS X")) {
            runtimeCommands = dsclCommands;
        } else {
            throw new AuthorizerCreationException(OS_TYPE_ERROR);
        }

        // Our second init step is to run the SYS_CHECK command from that
        // command set to determine if the other commands will work on
        // this host or not.
        try {
            runShell(runtimeCommands.get(Command.SYS_CHECK));
        } catch (final IOException ioexc) {
            logger.error("initialize exception: " + ioexc);
            throw new AuthorizerCreationException(SYS_CHECK_ERROR, ioexc.getCause());
        }

        // With our command set selected, and our system check passed,
        // we can pull in the users and groups:
        refreshUsers();
        refreshGroups();
        
        // Our last init step is to fire off the refresh threads per
        // the context:
        int initialDelay = 30, fixedDelay = 30;
        Runnable users = new Runnable () {
                @Override
                public void run() {
                    refreshUsers();
                }
            },

            groups = new Runnable () {
                @Override
                public void run() {
                    refreshGroups();
                }
            };

        // configurationContext.getProperty(PROP_USER_GROUP_REFRESH)
        scheduler.scheduleWithFixedDelay(users, initialDelay, fixedDelay, TimeUnit.SECONDS);
        scheduler.scheduleWithFixedDelay(groups, initialDelay, fixedDelay, TimeUnit.SECONDS);
    }

    /**
     * Called immediately before instance destruction for implementers to release resources.
     *
     * @throws AuthorizerDestructionException If pre-destruction fails.
     */
    @Override
    public void preDestruction() throws AuthorizerDestructionException {
        try {
            scheduler.shutdownNow();
        } catch (final Exception exc) {
        }
    }

    // End of the UserGroupProvider implementation.
    
    protected void setCommands(Map<Command, String> commands) {
        runtimeCommands = commands;
        refreshUsers();
        refreshGroups();
    }

    protected Map<Command, String> getCommands() {
        return runtimeCommands;
    }
    
    private void refreshUsers() {
        Map<String, User> byId = new HashMap<>();
        Map<String, User> byName = new HashMap<>();
        List<String> lines;

        try {
            lines = runShell(runtimeCommands.get(Command.USERS_LIST));
        } catch (final IOException ioexc)  {
            logger.error("refreshUsers shell exception: " + ioexc);
            return;
        }

        lines.forEach(line -> {
                String[] record = line.split(":");
                if (record.length > 1) {
                    String name = record[0],
                        id = record[1];
                    User user = new User.Builder().identity(name).identifier(id).build();
                    byId.put(id, user);
                    byName.put(name, user);
                }
            });

        synchronized (usersById) {
            usersById.clear();
            usersById.putAll(byId);
        }

        synchronized (usersByName) {
            usersByName.clear();
            usersByName.putAll(byName);
            logger.info("refreshUsers users now size: " + usersByName.size());
        }
    }

    private void refreshGroups() {
        Map<String, Group> groups = new HashMap<>();
        List<String> lines;

        try {
            lines = runShell(runtimeCommands.get(Command.GROUPS_LIST));
        } catch (final IOException ioexc) {
            logger.error("refreshGroups list groups shell exception: " + ioexc);
            return;
        }

        lines.forEach(line -> {
                String[] record = line.split(":");
                if (record.length > 1) {
                    Set<String> users = new HashSet<>();
                    String groupName = record[0], groupId = record[1];

                    try {
                        List<String> userLines = runShell(String.format(runtimeCommands.get(Command.GROUP_MEMBERS), groupName));
                        if (userLines.size() > 0) {
                            users.addAll(Arrays.asList(userLines.get(0).split(",")));
                        }
                    } catch (final IOException ioexc) {
                        logger.error("refreshGroups list membership shell exception: " + ioexc);

                    }
                    Group group = new Group.Builder().name(groupName).identifier(groupId).addUsers(users).build();
                    groups.put(groupId, group);
                }
            });

        synchronized (groupsById) {
            groupsById.clear();
            groupsById.putAll(groups);
            logger.info("refreshGroups groups now size: " + groupsById.size());
        }
    }

    private List<String> runShell(String command) throws IOException {
        final ProcessBuilder builder = new ProcessBuilder(new String[]{"sh", "-c", command});
        final Process proc = builder.start();
        final List<String> lines = new ArrayList<>();

        try {
            proc.waitFor(shellTimeout, TimeUnit.SECONDS);
        } catch (InterruptedException irexc) {
            throw new IOException(irexc.getMessage(), irexc.getCause());
        }

        if (proc.exitValue() != 0) {
            try (final Reader stderr = new InputStreamReader(proc.getErrorStream());
                 final BufferedReader reader = new BufferedReader(stderr)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    logger.error("" + line.trim());
                }
            }
            throw new IOException("Command exit non-zero: " + proc.exitValue());
        }

        try (final Reader stdin = new InputStreamReader(proc.getInputStream());
             final BufferedReader reader = new BufferedReader(stdin)) {
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line.trim());
            }
        }

        return lines;
    }
}
