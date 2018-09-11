import omemo

class DeletingOTPKPolicy(omemo.OTPKPolicy):
    @staticmethod
    def decideOTPK(preKeyMessages):
        # Always just delete the OTPK.
        # This is the behaviour described in the original X3DH specification.
        return False
