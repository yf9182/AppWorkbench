class WorkbenchError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)
