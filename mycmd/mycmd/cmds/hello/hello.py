# Import Python native modules your command will need

# Import MyCmdCommand to use to make your command
from ...mycmd import MyCmdCommand

# Example hello command
class Hello(MyCmdCommand):
    def handler(self, session, args=None):
        print("Hi Developers!")