package org.apache.nifi.authorization;

interface ShellCommandsProvider {
    String getUsersList();
    String getUserGroups();
    String getGroupsList();
    String getGroupMembers();
    String getSystemCheck();
}
