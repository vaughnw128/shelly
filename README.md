# Shelly
## An ICMP based C2 server

Shelly is an ICMP based C2 server that I wrote as a red team tool for my Cyber Defense Techniques class. This tool is intended for educational purposes only, and it's goal is to be used in red/blue team competitions.

Shelly is made up of three parts: A daemon, a controller, and an implant.

The project is named after the rift herald from League of Legends.

![shelly](https://media.tenor.com/0Wx4sAm11vcAAAAd/rift-herald-dance.gif)

### Daemon

The daemon is responsible for receiving join requests from the implant and storing those connections in a small database located in /var/lib/shelly/db.json. Once per minute, the daemon sends out heartbeat requests to check if the implants are still connected. If not, it disconnects them. This daemon gives a nice connection list to the controller.

### Controller

The controller is the mechanism by which the operator can communicate with the targets. This interaction comes in the form of a few commands:

- ls: List connected targets and modules
- rm: Remove a target or all targets
- interact: Interact with a specified target using the ICMP shell
- run: Runs an included module against a specified target or all targets
- broadcast: Broadcasts a message to all users on a target
- connect: Sends a connect command to all targets via the broadcast IP

### Implant

The implant is what actually sits on the target device and listens for commands from the daemon and controller. It's able to parse commands and execute them, then return the response to the controller, as well as listen for join and heartbeat commands to communicate with the daemon.

Auto built releases of the implant can be found under 'Releases' on github.

---

## Requirements and Building

It's reccomended to use pyinstaller to build the implant before deploying it on the target system. This can be done with pyinstaller.

First, install the required dependencies

`pip3 install -r requirements.txt`

Then run pyinstaller. This sould be run on the target OS that you intend to deploy it on.

`sudo pyinstaller -y --onefile ./src/implant.py`

Voila! Now, in dist/ you should have an implant executable.

---

## Usage

In order to use shelly, you first need to deploy the daemon and implants.
Once on the target systems, the implants can be run with `sudo ./implant`

From the C2 server, run the daemon with `sudo python3 shellyd.py`

Finally, the controller can be run.


```
     _          _ _
    | |        | | |
 ___| |__   ___| | |_   _
/ __| '_ \ / _ \ | | | | |
\__ \ | | |  __/ | | |_| |
|___/_| |_|\___|_|_|\__, |
                     __/ |
                    |___/
An ICMP based C2 server and agent

Usage: shelly.py command [-h|--help] [-t|--target] [-m|--module]
                 [-M|--message] [-v|--verbose]

Commands:
  ls            List connected targets
  rm            Remove a target
  interact      Interact with a specified target using the ICMP shell
  run           Runs an included module against a specified target or all targets
  broadcast     Broadcasts a message to all users on a target
  connect       Sends a connect command to all targets

Options:
  -h/--help     show this help message and exit
  -t/--target   The target to interact with/run modules on. Specifying 'all' will select ALL targets.
  -m/--module   The module to use for the run command
  -M/--message  The message to be sent with broadcast. Contain the string with quotation marks
  -v/--verbose  Verbosity argument
```

`sudo python3 shelly.py`

Note: All scripts must be run with sudo as it is required by scapy.