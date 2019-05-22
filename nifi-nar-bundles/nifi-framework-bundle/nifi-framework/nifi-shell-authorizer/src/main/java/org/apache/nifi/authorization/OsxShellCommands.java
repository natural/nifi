package org.apache.nifi.authorization;

class OsxShellCommands implements ShellCommandsProvider {
    public String getUsersList() {
        return "dscl . -list /Users UniqueID | grep -v '^_' | sed 's/ \\{1,\\}/:/g'";
    }

    public String getUserGroups() {
        return "id -nG %s | sed 's/\\ /,/g'";
    }

    public String getGroupsList() {
        return "dscl . -list /Groups PrimaryGroupID  | grep -v '^_' | sed 's/ \\{1,\\}/:/g'";
    }

    public String getGroupMembers() {
        return "dscl . -read /Groups/%s GroupMembership | cut -f 2- -d ' ' | sed 's/\\ /,/g'";
    }

    public String getSystemCheck() {
        return "which dscl";
    }
}
