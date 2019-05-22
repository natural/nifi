package org.apache.nifi.authorization;

class RemoteShellCommands implements ShellCommandsProvider {
    // Carefully crafted command replacement string:
    private final static String remoteCommand = "ssh " +
        "-o 'StrictHostKeyChecking no' " +
        "-o 'PasswordAuthentication no' " +
        "-o \"RemoteCommand %s\" " +
        "-i %s -p %s -l root %s";

    private ShellCommandsProvider innerProvider;
    private String privateKeyPath;
    private String remoteHost;
    private Integer remotePort;

    private RemoteShellCommands() {
    }

    public static ShellCommandsProvider wrapOtherProvider(ShellCommandsProvider otherProvider, String keyPath, String host, Integer port) {
        RemoteShellCommands remote = new RemoteShellCommands();

        remote.innerProvider = otherProvider;
        remote.privateKeyPath = keyPath;
        remote.remoteHost = host;
        remote.remotePort = port;

        return remote;
    }

    public String getUsersList() {
        return String.format(remoteCommand, innerProvider.getUsersList(), privateKeyPath, remotePort, remoteHost);
    }

    public String getUserGroups() {
        return String.format(remoteCommand, innerProvider.getUserGroups(), privateKeyPath, remotePort, remoteHost);
    }

    public String getGroupsList() {
        return String.format(remoteCommand, innerProvider.getGroupsList(), privateKeyPath, remotePort, remoteHost);
    }

    public String getGroupMembers() {
        return String.format(remoteCommand, innerProvider.getGroupMembers(), privateKeyPath, remotePort, remoteHost);
    }

    public String getSystemCheck() {
        return String.format(remoteCommand, innerProvider.getSystemCheck(), privateKeyPath, remotePort, remoteHost);
    }
}
