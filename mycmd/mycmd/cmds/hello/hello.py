
# Example hello command
class Command():
    desc = "Hello example command"

    def handler(self, session, args=None):
        print("Hi Developers!")