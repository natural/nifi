package org.apache.nifi.authorization;

class NssShellCommands implements ShellCommandsProvider {
    public String getUsersList() {
        return "getent passwd | cut -f 1,3 -d ':'";
    }

    public String getUserGroups() {
        return "id -nG %s | sed s/\\ /,/g";
    }

    public String getGroupsList() {
        return "getent group | cut -f 1,3 -d ':'";
    }

    public String getGroupMembers() {
        return "getent group %s | cut -f 4   -d ':'";
    }

    public String getSystemCheck() {
        return "getent passwd"; // this gives exit code 0 on distros tested.
    }
}
