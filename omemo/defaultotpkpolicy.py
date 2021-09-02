import copy

from .otpkpolicy import OTPKPolicy

class DefaultOTPKPolicy(OTPKPolicy):
    """
    An implementation of the OTPKPolicy with a default ruleset that slightly prefers
    usability over security.

    These are the rules:
    * Never delete an OTPK because of messages that came from some sort of storage
        mechanism like MAM
    * Never delete an OTPK as long as you have not sent a single answer
    * Only delete an OTPK if at least two answers were sent with a delay of at least 24
        hours between them

    With this ruleset possible attackers are prevented from permanently reusing an OTPK,
    while real-world use-cases should never result in lost messages because of deleted
    OTPKs.

    You can use the additional_information parameter of the SessionManager.decryptMessage
    method to declare whether a message came from some storage mechanism like MAM or not.
    To do so, pass additional_information like this::

        additional_information = {
            "from_storage": boolean
        }
    """

    @staticmethod
    def decideOTPK(preKeyMessages):
        pkms = copy.deepcopy(preKeyMessages)

        # Normalize the additional_information to contain an empty dict instead of None
        for pkm in pkms:
            if pkm["additional_information"] == None:
                pkm["additional_information"] = {}

        # Normalize the from_storage information
        for pkm in pkms:
            if not "from_storage" in pkm["additional_information"]:
                pkm["additional_information"]["from_storage"] = False

        # Filter out messages that were retreived from storage mechanisms
        pkms = list(filter(
            lambda pkm: not pkm["additional_information"]["from_storage"],
            pkms
        ))

        # Collect all answers
        answers = []

        for pkm in pkms:
            answers += pkm["answers"]

        # Check whether at least two answers were sent
        if len(answers) < 2:
            return True

        # Check whether at least 24 hours passed between the two answers
        elapsed_seconds = max(answers) - min(answers)
        elapsed_minutes = elapsed_seconds / 60
        elapsed_hours   = elapsed_minutes / 60

        if elapsed_hours < 24:
            return True

        # Otherwise, all conditions are met to delete the OTPK
        return False
