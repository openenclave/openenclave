# Debugging Enclaves on OP-TEE OS with QEMU on WSL

This document is a complement to
[Debugging Enclaves on OP-TEE OS with QEMU](QEMU.md). That guide assumes it is
being followed on a native Linux system. This guide shows you how to configure
the Windows Subsystem for Linux (WSL) to use the guide on WSL.

In this guide, you will learn how to:

1. Install and configure a native X Server;
2. Work around a UNIX feature used by `fakeroot`
[not yet implemented in WSL](https://github.com/Microsoft/WSL/issues/1443).

# Prerequisites

This guide presumes you have a Windows 10 installation, version 1803 or later.

## Required Features and Apps

WSL is not installed by default. To install it, launch PowerShell as
Administrator and run:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
```

Restart your computer when prompted.

You are now ready to install [Ubuntu
18.04](https://www.microsoft.com/en-us/p/ubuntu-1804-lts/9n9tngvndl3q) on WSL.

For a visual guide to this process, see [Install the Windows Subsystem for
Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10#install-the-windows-subsystem-for-linux).

After Ubuntu 18.04 is installed, launch it from the Start Menu. The first launch
takes some time while the root filesystem is decompressed. Follow the
instructions on screen to set up an account inside the Ubuntu 18.04 environment.
Once that is complete, update the environment as follows:

```bash
sudo apt update && sudo apt upgrade -y
```

## X Server

The build system for the QEMU debugging environment launches two instances of
XTerm. XTerm is a graphical application for X11, or simply X. X is a
client-server windowing system where a graphical application runs on a remote
machine and is rendered on a thin terminal. This is not too dissimilar in
practice to Windows Server with Terminal Services. In X terminology, the server
is the thin terminal where output is rendered and the client is an application
running on a remote machine. In typical Linux distributions, the client and
server both run on the same computer.

For the purposes of this guide, you will install an X Server that runs outside
of WSL. Then, you will let the build system launch XTerm inside WSL normally.
XTerm will connect to the X server outside of WSL over a local network
connection and render as a normal window on your Windows desktop.

WSL does not ship with an X Server so you must install one yourself.
[XMing](http://www.straightrunning.com/XmingNotes) is a cross-compiled version
of X for Windows and is known to work well. The public domain releases are free
to use.

**Note:** The author of XMing does not provide signed binaries. You may choose a
different X Server implementation if you prefer; the configuration steps below
should be the same if the alternative implementation that you choose is
compliant with the X protocol.

Launch the installer and follow the instructions on screen.

Once XMing is installed, a folder of the same name is added to the Start Menu.
Be sure to use the "XMing" shortcut, not "XLaunch". If you are prompted by the
Windows Defender Firewall after launching XMing to allow it to communicate over
the network, click "Cancel". This configures the firewall to deny all incoming
connections to XMing, but local connections are not affected.

The only indication that XMing has successfully started is an icon in the
notification area.

# Building & Debugging in WSL

Before you are able to follow the steps in the debugging guide, execute the
following command inside the Ubuntu 18.04 environment:

```bash
echo "export DISPLAY=:0" >> ~/.bashrc
exit
```

**Note:** You need only do this once.

X applications read the `DISPLAY` environment variable to determine what X
Server to connect to. The value `:0` is shorthand for `localhost:0`, where
`localhost` is the network address of the machine where the X Server is running
on and `0` indicates the display number. You must exit and re-enter the Ubuntu
18.04 environment for Bash to pick up the changes to `.bashrc`. Afterward, the
`DISPLAY` variable will always be set.

You may now follow the [Debugging Enclaves on OP-TEE OS with QEMU](QEMU.md)
guide on WSL.

After some time into the build process of the QEMU debugging environment, it
will stop suggesting that `fakeroot` failed.

## Fakeroot

The build environment uses its own version of `fakeroot`. This version attempts
to make use of SYS-V IPC, but this feature is not available on WSL. You will see
an error that reads:

```
fakeroot, while creating message channels: Function not implemented
This may be due to a lack of SYSV IPC support.
fakeroot: error while starting the `faked' daemon.
```

To work around this issue, replace the `fakeroot` binary that the build system
uses with the version of `fakeroot` that uses sockets for IPC instead. Ubuntu
18.04 ships with both versions.

Run the following commands to replace `fakeroot` with its socket-based
counterpart:

```bash
mv $HOME/openenclave_qemu/emulation/out-br/host/bin/fakeroot $HOME/openenclave_qemu/emulation/out-br/host/bin/fakeroot.bak
ln -s /usr/bin/fakeroot-tcp $HOME/openenclave_qemu/emulation/out-br/host/bin/fakeroot
```

Resume the build with `make run` (and `-j`, as appropriate). If you ever clean
and rebuild the Buildroot output, you will run into this issue again. However,
that is never required for the purposes of debugging enclaves. In general,
therefore, this is a one-time fix.

The Windows Defender Firewall might prompt for permission to allow incoming
connections to various Linux programs as the build proceeds. None of these
programs require accepting remote requests, so you can safely click "Cancel" to
block all incoming connections. Just as with XMing, local connections are not
affected.
