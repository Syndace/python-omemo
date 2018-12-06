class EncryptionProblemsException(Exception):
    def __init__(self, problems):
        self.__problems = problems

    @property
    def problems(self):
        return self.__problems
