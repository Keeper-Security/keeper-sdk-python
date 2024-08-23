import argparse
import os

from keepercli import commands, login
from keepersdk.authentication import endpoint
from keepersdk.authentication import configuration


class LoginContext:
    def __init__(self):
        self.server = ''

class NonConnectedPrompt(commands.CommandPrompt[LoginContext]):
    def __init__(self):
        super().__init__()
        self.context = LoginContext()
        sc: commands.ICommand[LoginContext] = commands.GetterSetterCommand('server', 'Keeper region')
        self.register_command(sc, 'server')

    def get_prompt(self) -> str:
        return 'Not logged in'

    def get_context(self) -> LoginContext:
        return self.context
        
    


config_file = os.path.join(os.path.dirname(__file__), 'config.json')
config_storage = configuration.JsonConfigurationStorage.from_file(config_file)
keeper_endpoint = endpoint.KeeperEndpoint(config_storage)


login_flow = login.LoginFlow()

