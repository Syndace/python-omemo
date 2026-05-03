from typing import Final

import twomemo
import oldmemo


__all__ = [
    "NS_TWOMEMO",
    "NS_OLDMEMO",
    "ALICE_BARE_JID",
    "BOB_BARE_JID"
]


NS_TWOMEMO: Final = twomemo.twomemo.NAMESPACE
NS_OLDMEMO: Final = oldmemo.oldmemo.NAMESPACE

ALICE_BARE_JID: Final = "alice@example.org"
BOB_BARE_JID: Final = "bob@example.org"
