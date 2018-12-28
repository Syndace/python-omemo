from .sessionmanagerexception import SessionManagerException

class EncryptionProblemsException(SessionManagerException):
    def __init__(self, problems):
        self.__problems = problems

    @property
    def problems(self):
        return self.__problems

    def __str__(self):
        if len(self.__problems) == 1:
            return (
                "There was a problem during message encryption: {}"
                .format(self.__problems[0])
            )
        else:
            return (
                "There were {} problems during message encryption: {}"
                .format(len(self.__problems), self.__problems)
            )
