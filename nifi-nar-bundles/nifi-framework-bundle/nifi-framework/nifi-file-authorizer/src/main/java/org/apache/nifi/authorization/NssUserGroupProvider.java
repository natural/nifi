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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import java.lang.InterruptedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;

import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import org.apache.nifi.authorization.annotation.AuthorizerContext;
import org.apache.nifi.authorization.exception.AuthorizationAccessException;
import org.apache.nifi.authorization.exception.AuthorizerCreationException;
import org.apache.nifi.authorization.exception.AuthorizerDestructionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Concrete implementation of UserGroupProvider using
 * ShellUserGroupProvider as the base.
 */
public class NssUserGroupProvider extends ShellUserGroupProvider {
    {
	GET_GROUP  = "getent group '%s'  | cut -f 1,3,4 -d ':'";
	GET_GROUPS = "getent group       | cut -f 1,3,4 -d ':'";	
	
	GET_USER   = "getent passwd '%s' | cut -f 1,3 -d ':'";
	GET_USERS  = "getent passwd      | cut -f 1,3 -d ':'";
	
	SYS_CHECK = "which getent";
	SYS_CHECK_ERROR = "System does not support 'getent' command.";
    }
}


/**
 * move this to OsxUserGroupProvider.java
 */
class OsxUserGroupProvider extends ShellUserGroupProvider {
    {
	SYS_CHECK = "which getent";
	// etc
    }
}


/*
 * ShellUserGroupProvider implements UserGroupProvider by way of bash commands.
 */
abstract class ShellUserGroupProvider implements UserGroupProvider {
    private final static Logger logger = LoggerFactory.getLogger(ShellUserGroupProvider.class);
    
    String GET_GROUP  = "";
    String GET_GROUPS = "";	
    String GET_USER   = "";
    String GET_USERS  = "";
    String SYS_CHECK = "";
    String SYS_CHECK_ERROR = "";

    final Set<User> users = new HashSet<>();
    final Set<Group> groups = new HashSet<>();
    
    // Start of the UserGroupProvider implementation.  Docstrings
    // copied from the interface definition.

    /**
     * Retrieves all users. Must be non null
     *
     * @return a list of users
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public Set<User> getUsers() throws AuthorizationAccessException {
	// Set<User> users;
	// try {
	//     users = outputToUsers(runShell(this.GET_USERS));
	// } catch (final IOException ioexc) {
	//     logger.error("getUsers exception: " + ioexc);
	//     throw new AuthorizationAccessException(ioexc.getMessage(), ioexc.getCause());	    
	// }
	
	logger.debug("getUsers has user set of size: " + users.size());
	return users;
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
	User user;
	
	try {
	    user = outputToUser(runShell(String.format(GET_USER, identifier)));
	} catch (final IOException ioexc) {
	    logger.error("getUser exception: " + ioexc);
	    throw new AuthorizationAccessException(ioexc.getMessage(), ioexc.getCause());
	}
	
	logger.debug("getUser has user: " + user);
	return user;
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
	// NB: the shell commands we're using accept either uid or
	// username, so we can just alias this call:
	return getUser(identity);
    }

    /**
     * Retrieves all groups. Must be non null
     *
     * @return a list of groups
     * @throws AuthorizationAccessException if there was an unexpected error performing the operation
     */
    @Override
    public Set<Group> getGroups() throws AuthorizationAccessException {
	// Set<Group> groups;
	
	// try {
	//     groups = outputToGroups(runShell(GET_GROUPS));
	// } catch (final IOException ioexc) {
	//     logger.error("getGroups exception: " + ioexc);
	//     throw new AuthorizationAccessException(ioexc.getMessage(), ioexc.getCause());
	// }
	
	logger.debug("getGroups has group set of size: " + groups.size());
	return groups;
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
	Group group;
	
	try {
	    group = outputToGroup(runShell(String.format(GET_GROUP, identifier)));
	} catch (final IOException ioexc) {
	    logger.error("getGroup exception: " + ioexc);
	    throw new AuthorizationAccessException(ioexc.getMessage(), ioexc.getCause());
	}
	
	logger.debug("getGroup has group: " + group);
	return group;
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
	    Set<Group> groups = groupsOf(identity);
	    
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
	try {
	    runShell(SYS_CHECK);
	} catch (final IOException ioexc) {
	    logger.error("initialize exception: " + ioexc);
	    throw new AuthorizerCreationException(SYS_CHECK_ERROR, ioexc.getCause());
	}
	
	ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
	scheduler.scheduleWithFixedDelay(new Runnable () {
		@Override
		public void run() {
		    try {
			users.clear();
			users.addAll(outputToUsers(runShell(GET_USERS)));
		    } catch (final IOException ioexc) {
		        logger.error("scheduled get users shell exception: " + ioexc);
		    }
		}
	    }, 
	    0,  // no initial delay
	    30, // thirty seconds in between runs
	    TimeUnit.SECONDS);
	
	scheduler.scheduleWithFixedDelay(new Runnable () {
		@Override
		public void run() {
		    try {
			groups.clear();
			groups.addAll(outputToGroups(runShell(GET_GROUPS)));
		    } catch (final IOException ioexc) {
			logger.error("scheduled get groups shell exception: " + ioexc);
		    }
		}
	    }, 
	    0,  // no initial delay
	    30, // thirty seconds in between runs
	    TimeUnit.SECONDS);
    }

    /**
     * Called to configure the Authorizer.
     *
     * @param configurationContext at the time of configuration
     * @throws AuthorizerCreationException for any issues configuring the provider
     */
    @Override
    public void onConfigured(AuthorizerConfigurationContext configurationContext) throws AuthorizerCreationException {
    }

    /**
     * Called immediately before instance destruction for implementers to release resources.
     *
     * @throws AuthorizerDestructionException If pre-destruction fails.
     */
    @Override
    public void preDestruction() throws AuthorizerDestructionException {
        try {
            executor.shutdownNow();
	} finally {
            if (this.externalProcess.isAlive()) {
                // this.getLogger().info("Process hasn't terminated, forcing the interrupt");
                this.externalProcess.destroyForcibly();
            }
        }
    }

    // End of the UserGroupProvider implementation.
    
    private Set<Group> groupsOf(String identity) {
	Set<Group> groups = getGroups();
	return groups;
    }

    private static List<String> runShell(String command) throws IOException {
	final ProcessBuilder builder = new ProcessBuilder(new String[]{"bash", "-c", command});
	final Process proc = builder.start();
	// externalProcess = proc
	    
        final List<String> lines = new ArrayList<>();

	try {
	    proc.waitFor(30, TimeUnit.SECONDS);
	} catch (InterruptedException irexc) {
	    throw new IOException(irexc.getMessage(), irexc.getCause());
	}
	
        try (final InputStream stdin = proc.getInputStream();
             final BufferedReader reader = new BufferedReader(new InputStreamReader(stdin))) {
	    
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line.trim());
            }
        }
	
	if (proc.exitValue() != 0) {
	    throw new IOException("Command exit non-zero: " + proc.exitValue());
	}
	
        return lines;
    }


    private volatile ExecutorService executor;
    private Future<?> longRunningProcess;
    private AtomicBoolean failure = new AtomicBoolean(false);
    // private volatile ProxyOutputStream proxyOut;
    private volatile Process externalProcess;
    
    private Set<User> outputToUsers(List<String> lines) {
	Set<User> users = new HashSet<>();
	
	lines.forEach(line -> {
		String[] record = line.split(":");
		if (record.length > 1) {
		    users.add(new User.Builder().identity(record[0]).identifier(record[1]).build());
		}
	    });
	
	return users;
    }
    
    private User outputToUser(List<String> lines) {
	if (lines.size() == 1) {
	    return outputToUsers(lines).iterator().next();
	}
	
	return null;
    }

    private Set<Group> outputToGroups(List<String> lines) {
	Set<Group> groups = new HashSet<>();
	
	lines.forEach(line -> {
		String[] record = line.split(":");
		if (record.length > 1) {
		    
		    Set<String> users = new HashSet<>();
		    if (record.length > 2) {
			users = Arrays.stream(record[2].split(",")).collect(Collectors.toSet());
		    }
		    groups.add(new Group.Builder().name(record[0]).identifier(record[1]).addUsers(users).build());
		}
	    });
	
	return groups;
    }
    
    private Group outputToGroup(List<String> lines) {
	if (lines.size() == 1) {
	    return outputToGroups(lines).iterator().next();
	}
	
	return null;
    }
}
