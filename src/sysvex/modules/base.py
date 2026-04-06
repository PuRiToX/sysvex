class BaseModule:
    name = "base"

    def run(self, context=None):
        raise NotImplementedError
