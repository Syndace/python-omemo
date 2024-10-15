from typing import Dict, List, Optional, cast
from xml.etree import ElementTree as ET

import oldmemo
import oldmemo.etree
from oldmemo.migrations import LegacyStorage, OwnData, State, Session, Trust
from typing_extensions import Final

import omemo

from .data import ALICE_BARE_JID, BOB_BARE_JID


__all__ = [
    "POST_MIGRATION_TEST_MESSAGE",
    "download_bundle",
    "LegacyStorageImpl"
]


POST_MIGRATION_TEST_MESSAGE: Final = """
<encrypted xmlns='eu.siacs.conversations.axolotl'>
    <header sid='254614318'>
        <key rid='1640101268'>
            MwohBcFF45Qdk0tyhmB+c76mXSegKveJzATYysVTHUCyYbEAEAUYACIwIaDnrczm27Lzgv6J7p7rp/DWpyujtoPHrkWO5JclBX
            /ZE+owYcXbhMfdYbgd+JK4LOiY0WazRJA=
        </key>
        <key rid='1895030716'>
            MwohBTbC1RAbbHF6deJQPG4eB6OAGTmJJNUEiTXM6Q46QkxpEAIYACIwXvPCTr2QPWZxWZUFGNW6ZPPvi+iPp5NmT5WqceRs6m
            3uPwh2/BFRfpwjP4uI/VEVoQyXXE8DTOY=
        </key>
        <key rid='276148623'>
            MwohBZBjEgjnFvHyOSaaovOj2MsrcPiQxPeqRI0Dqyzg05F1EAMYACIwDEJdq3CG3gzEXQNzUnQRwHpXWnwIZwt1nyg7Dbyi5C
            jO787BDQvQaIQqL0CHoznQZnXAeIDguZo=
        </key>
        <key rid='543990483'>
            MwohBf7heasdh5ektESIPHQQm/UyO1NQ7x/RaA2Q+Ayu/utzENgCGAAiMGH5l7tCMmsptsJ4Ptewj5EH23ssZWrSkgsF5lID9j
            +whRVOK2Vwsz+2GqnP2HE7nEWNnwXI6zV2
        </key>
        <key rid='1746810996'>
            MwohBYRh6M6pQCVUQqHM9iMTp6IVNiQO7wAxCtBOyFXZfo1cEAEYDCIw+WKASQdTDyIgurF9r1d4rHg7/vFXiMfIYn1xcDxLXY
            3s6zyk6sAnVfLDJQkxkHPOzLqcjjcrHi0=
        </key>
        <iv>Gtucn9MhRg3XYKwP</iv>
    </header>
    <payload>MnyPie/eh2jU+MYG6UEGeKsMkJ+VUg==</payload>
</encrypted>
"""


async def download_bundle(bare_jid: str, device_id: int) -> oldmemo.oldmemo.BundleImpl:
    """
    Helper for the migration test which simply raises :class:`omemo.BundleDownloadFailed` whenever a bundle
    download is requested.
    """

    bundle_xml: Optional[str] = None

    if bare_jid == ALICE_BARE_JID:
        if device_id == 1895030716:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='3'>
        BYvlcUe/XCzNPYtipShgRFBQ3SulK65zFROfCfgYDHkr
    </signedPreKeyPublic>
    <signedPreKeySignature>
        +eaMwcaY2tgegarMC33bgzy0gIdfIf1QiAZwlxge4t9FxYzHH1I6ZF3s1ETGs5Gm2v+Q8jw/AU/OwrLBVbnmiw==
    </signedPreKeySignature>
    <identityKey>Bea/qneH5GO9JWV486GPweRyxSrykVOK5AAtSl7PC4EC</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='67'>BRinf3hEatGLxmd+RuqX3esYrPTiIRh/cEWkgei5H9Q/</preKeyPublic>
        <preKeyPublic preKeyId='70'>BSdmWsm+TU8B4+0Blm+5QHMhkslJvehHYkdyNVm5t9FJ</preKeyPublic>
        <preKeyPublic preKeyId='6'>BVkmoCPn1B2/8diCRuwFLmBoaOLrMLlxtQ288pk9YB95</preKeyPublic>
        <preKeyPublic preKeyId='66'>BRqanvmShrNpsqgmRxpQPKP5evTT+CZuN263jvU+DnxV</preKeyPublic>
        <preKeyPublic preKeyId='75'>BbrUDWNOcIE62SoEB6ZujGZX1hBSFriirTdRjUwOZ/sT</preKeyPublic>
        <preKeyPublic preKeyId='50'>BQFgb+CbtjPcbsO6B23evZkAfJas9mWhbwDksetABAJB</preKeyPublic>
        <preKeyPublic preKeyId='28'>BVGLXD9d8ZxMPVyAr5b67wYD32NOUjp5JctNJbPvNMcZ</preKeyPublic>
        <preKeyPublic preKeyId='69'>BVmcKsQ9aEdRMH4v5zv9+xVvTrx7VpfmCuTUOvh8AUls</preKeyPublic>
        <preKeyPublic preKeyId='82'>BVIXhqfw4o3jOOtebgnKug8TqcVKTh1BCWya8yTAXeB1</preKeyPublic>
        <preKeyPublic preKeyId='98'>BdHFzoe546NFD16N7NoUUIdtSxvyXX2YvKA+lq/fiPIv</preKeyPublic>
        <preKeyPublic preKeyId='80'>BaohsoRRyOZzKkFupJDzD6+/BBlUnq+y6yeoGrzFI+F+</preKeyPublic>
        <preKeyPublic preKeyId='32'>BcpxJ9Q6EL/lx/WYZyiR03fHC28+5Yz2xOxU4qDDny8d</preKeyPublic>
        <preKeyPublic preKeyId='76'>Behl5Z2AvOaJQKxk1Gfrt3ulf/SXZVSErouiuc5NlFd8</preKeyPublic>
        <preKeyPublic preKeyId='13'>BUHRf/n4WzsJyA3IyVstsAylEdrhaKXhzVRyWdA4vP99</preKeyPublic>
        <preKeyPublic preKeyId='47'>BcmfsLuU8/zDuR4ZbY+olkgCfjFjA7c7s9sOw5yIpe9v</preKeyPublic>
        <preKeyPublic preKeyId='87'>BUiqFEIlghZSHZDW/WGpH6W8sPJ7riJNk9NoFQghO40E</preKeyPublic>
        <preKeyPublic preKeyId='8'>Bb10cJcPi5d6tVzWbIChJpBgyvVjOKY3+SDlFTI9FSZi</preKeyPublic>
        <preKeyPublic preKeyId='89'>Bb4ZgebgoxEq9ap9JSvup1k/9mwTQAqe4ZXGyM/hTT88</preKeyPublic>
        <preKeyPublic preKeyId='65'>BSqkALZBuBmalsOdMeNQ7gyT9cMYVoLpu1hnFq18foQ3</preKeyPublic>
        <preKeyPublic preKeyId='49'>BS2Cajt66kKYObf/OU3YwNJn0WDfducVz3TWVWGmbZ5K</preKeyPublic>
        <preKeyPublic preKeyId='26'>BTCiWXfshVIDOIhq7ffssao0Yl9S9B3aNmmhhtC1L5gZ</preKeyPublic>
        <preKeyPublic preKeyId='37'>BatbSyms4aMouq7qVvdLyRPVgV5WKc5aQzNiWvXwCjJq</preKeyPublic>
        <preKeyPublic preKeyId='42'>BURUc+26Py2SZRVVkI+N0bx96ffpDLca6thK6qgqPeMl</preKeyPublic>
        <preKeyPublic preKeyId='90'>Bb0Vkwv5Klo53gWZQICy3HBF9uixZciV2u+t81r3fBQD</preKeyPublic>
        <preKeyPublic preKeyId='1'>BRKgge6xfvrWcScDRgO+q2Y14yH0FX3+SLlU9lyVX858</preKeyPublic>
        <preKeyPublic preKeyId='44'>BaBJPrS5GwdPBzT+7p5w5m99fAk0OreQq98A9X7g7Ew8</preKeyPublic>
        <preKeyPublic preKeyId='86'>Bf15UqV3MG6VJ8T4i1uXM8VDjkT/CiAv/vhpG0fjeERz</preKeyPublic>
        <preKeyPublic preKeyId='153'>BQWWwiqJoultW6l2/yhz38K+KT8YN2KIBVQmeYHfz34f</preKeyPublic>
        <preKeyPublic preKeyId='97'>BTng6JpMTtEE2QgIlDKIQKdKROzlLEi2MvexDAGCzOMj</preKeyPublic>
        <preKeyPublic preKeyId='40'>BcgTBWa9ueF4/3iSEalGCbyYF0dAvYMv64BytLNKnq4v</preKeyPublic>
        <preKeyPublic preKeyId='53'>BfbxyKUbIIRG0AiplcNnSDU9t7aUNjTOd1rASeW7FsFv</preKeyPublic>
        <preKeyPublic preKeyId='61'>BcNUbHieArGtET/Nbs9TyaCsKR+h8tkqHnoVETmzIVRd</preKeyPublic>
        <preKeyPublic preKeyId='45'>BQILdO0kxTRM6uGEwmOGrd1eHICYpo4YNKm9vY3Lr6hj</preKeyPublic>
        <preKeyPublic preKeyId='23'>BQYCwqtcaEcvxyqfi9AtTE+B9TrZXmn3vNOr/KSF+Rkt</preKeyPublic>
        <preKeyPublic preKeyId='68'>BTfW8p2/EUW3cI9DEnLWFQKzhoXJpx1GSz724JCb9IVW</preKeyPublic>
        <preKeyPublic preKeyId='17'>BVuN0qgDdcAgV1WayUWE7Lll4HLgT8r460kCJ1msq/Nz</preKeyPublic>
        <preKeyPublic preKeyId='11'>BUH2l7qk2kN451oqDROb6KU12Rp6RTVcTbd3KiaCxVB+</preKeyPublic>
        <preKeyPublic preKeyId='12'>Bcr/EHhcxtHRbB9J1unSyI8DLlMiqUm58o5sY7OKTQIf</preKeyPublic>
        <preKeyPublic preKeyId='33'>BaaWFy8nGi7zP+ZN4Xj34qPwNJ65LANc+0aM7LarhJFS</preKeyPublic>
        <preKeyPublic preKeyId='92'>BdrKT+Ux2fnNdEEjAB9Zlr6Bw0QsFQoKFOO1CrVxsbYx</preKeyPublic>
        <preKeyPublic preKeyId='83'>BaXUiFv2Qe/Gq99S2M9ROPUgVDstlEIFIu/n17YztYBv</preKeyPublic>
        <preKeyPublic preKeyId='10'>Ba7OGuPuv6NaMLTmsW0SOLrvjJt1gt/Mxigtx8c6VNFa</preKeyPublic>
        <preKeyPublic preKeyId='77'>BY5HcOqjyoRL48zhi5uLoSwp+GLZy9KYdabX6DPzs6Uh</preKeyPublic>
        <preKeyPublic preKeyId='79'>BSi5zHp8BXflrwMa6MRcdnRJDRUsRf/KSzOxPmB1c7w6</preKeyPublic>
        <preKeyPublic preKeyId='29'>BafEvNE/PwpUHj/JMZWA0IgwpBd6+SFt0g3rQNl6McV2</preKeyPublic>
        <preKeyPublic preKeyId='96'>BYFTjQTaY/cz8yhE8iCXm/2yCR/F3BXZ941RZjJhCGdZ</preKeyPublic>
        <preKeyPublic preKeyId='7'>Bd2c3R/5i4zNQ45iUMV1VyqsnjbTd416bgcPV/B9F8Ar</preKeyPublic>
        <preKeyPublic preKeyId='3'>BSef/npZwyrPoNocFtPXWIZPviJrmFH5KYUAAxDa93tc</preKeyPublic>
        <preKeyPublic preKeyId='41'>BRqFk7nYRWtsGyVFlT9h8Z6CxRzR9N14aSWxLNik0sJj</preKeyPublic>
        <preKeyPublic preKeyId='88'>BUwYg0eSSI4TTvl+kOUHaKLVXfYcdsUsdmEgRjba9vMU</preKeyPublic>
        <preKeyPublic preKeyId='4'>BfoXqzM2NoHPw6XMYdCaMxrZZYHPI31ObWyf+BDxNoNf</preKeyPublic>
        <preKeyPublic preKeyId='18'>BRVCZHgjw3TywVCzmMCV1NS3FG/MX4CJlYEMBayvIily</preKeyPublic>
        <preKeyPublic preKeyId='35'>BWzoOPJxOQBPU0aYoDTTam5t5yZ6MGXiQhuAo7e3QEpj</preKeyPublic>
        <preKeyPublic preKeyId='52'>BfbtEEdKSAlfP7pFPV1LOKNYjHCMfSFnQIa/E15CaX4D</preKeyPublic>
        <preKeyPublic preKeyId='15'>BRZJmzb1B6JySfEbe/bnkhm6BiEm3ji2/yorDsOe6qNv</preKeyPublic>
        <preKeyPublic preKeyId='2'>BYX3pOd8HYaXJsvbkoKjG6FtNUBhPytXzZhC16qeRCZY</preKeyPublic>
        <preKeyPublic preKeyId='62'>BW2rP62LK7Yt12UOvVENmqUR7LpQ1uen0vMWKHWVzHZS</preKeyPublic>
        <preKeyPublic preKeyId='20'>BfZwAD7loZEdxPXB4rCBRHaafJMwy32CSnNfAHngH3Jm</preKeyPublic>
        <preKeyPublic preKeyId='58'>BbQpCaHIdoLeCF+fO82Sh2Qea4xtrg++h0iDq2aPsPUw</preKeyPublic>
        <preKeyPublic preKeyId='14'>BetX3831o0PD5mKYJKMlRda9H2dgrSjmFcaqaGcHrZJu</preKeyPublic>
        <preKeyPublic preKeyId='74'>BfEcKoKVQzbkVC1s/aTb+jpRLx5tUdigs62XyFpad5k4</preKeyPublic>
        <preKeyPublic preKeyId='95'>BapuKNQ5lx0jwmC87+Im4HPAvogQb+f9xkJiN1Bail4d</preKeyPublic>
        <preKeyPublic preKeyId='64'>BakgsvDJT3eSOsi8pjAi88ITdj57jqGCVO87n4HXHsZR</preKeyPublic>
        <preKeyPublic preKeyId='21'>BYtUfTbm1goqqu62ydlcR52miOle8fQ4AVJc2wSOMWx8</preKeyPublic>
        <preKeyPublic preKeyId='59'>BVvAuJaQmFPP+fQdIr3Js1BRUi3h1tTPPJ2lDvj4ih9Z</preKeyPublic>
        <preKeyPublic preKeyId='24'>BQw786+0nKQ3GpM383Fru6/yhZqTPr/KaIfvxNvYg7E2</preKeyPublic>
        <preKeyPublic preKeyId='99'>BeWLwfiEeniBcIhd4mYOOz2PmlWBk9qVWikKfhW09wY3</preKeyPublic>
        <preKeyPublic preKeyId='39'>BdyF9FWp/ocWQqZwWwSbe7x2uL5J5u3IP5mP8Ajcna8O</preKeyPublic>
        <preKeyPublic preKeyId='94'>BWUHD26yAkc1KNqzVoeIkzevvh8nq0hHCz0nTnImfcND</preKeyPublic>
        <preKeyPublic preKeyId='54'>Bat83dhwLCk4uQHeGbKzz0lEtptnYZm9JXTJPdOH5wYB</preKeyPublic>
        <preKeyPublic preKeyId='22'>BeqNw6bSWdHaOl/hrc9g7W6T9+YhGiAR0dGYJAxTEEw7</preKeyPublic>
        <preKeyPublic preKeyId='248'>Bf6xXlFTJziOUCkrkgxBs0O7su+TSR71sJgNPKBjPCpP</preKeyPublic>
        <preKeyPublic preKeyId='51'>BUVtAwG9LDnheCTQVtcO3q0GWBrFs0xV3F2L75ndsz4J</preKeyPublic>
        <preKeyPublic preKeyId='72'>BbSJ6PS1y+F2r2t1LcH35Wv2ZeEP+Ff8qqtEXNVil611</preKeyPublic>
        <preKeyPublic preKeyId='81'>BS7Q7BWEQn2H2+5rtTsU+ck2dXI0DXTox5wFppABWi9v</preKeyPublic>
        <preKeyPublic preKeyId='85'>BYG+QTYRQGgSIGE0AKNSiVh3aLIc0ePOpUAkW+VOWYE7</preKeyPublic>
        <preKeyPublic preKeyId='36'>BW+kJHdM0VRe4Dyk/rIakvwMRKPkYyqFio0S53Ynh7Mw</preKeyPublic>
        <preKeyPublic preKeyId='100'>BVIdgTjqS6i9pfgoTzSLI1BvmT+71x9noSHKZi254e1Z</preKeyPublic>
        <preKeyPublic preKeyId='84'>BVh+SmDvDA+0kNWZ3N3OZgXvTarnUv+GfI7HfMMYoCZr</preKeyPublic>
        <preKeyPublic preKeyId='31'>BaTgjz0McvcjZshq5jfyO4QIz0tVKlXvXhocs9Mys49W</preKeyPublic>
        <preKeyPublic preKeyId='71'>BdmbxO7dB6iSdTedLMKr6kEz4qflYkqyr0kNRpXInJkQ</preKeyPublic>
        <preKeyPublic preKeyId='56'>BWmtw2JQpTLqW4ATGMlyXHmyBuXiv9Yv45Dw4QB3gN9g</preKeyPublic>
        <preKeyPublic preKeyId='43'>BSMwfMb/17/29XEnrMEG61AT3XRwOlsvIrakxcR3vbc/</preKeyPublic>
        <preKeyPublic preKeyId='73'>BQU8kLFOEsNE3JScNttC+xuTavgy9LRMu0JsNiFmW74/</preKeyPublic>
        <preKeyPublic preKeyId='25'>BUhuIwl7sFZiQJ6BvBUOZzyfCgUM9kgGP+5pH4v4vhd5</preKeyPublic>
        <preKeyPublic preKeyId='38'>BaRLvhbWAoAu1C6J+r0Kz9Njb+bQWCeJS5aB2LXNX8RZ</preKeyPublic>
        <preKeyPublic preKeyId='91'>BWyY20o15AkNVcW1sx/9d1LHwwzSHS8mg0NSu6gFYWk+</preKeyPublic>
        <preKeyPublic preKeyId='93'>BRcypE14PRkxoOwpzGyL1OFH4p14/3E75Hj7hZFVeJol</preKeyPublic>
        <preKeyPublic preKeyId='60'>BQsPi2PZYA+xo3fB3TYs4d+NqBDvBIf0c6vVhKpcLU92</preKeyPublic>
        <preKeyPublic preKeyId='16'>BfymwBsVN96kgug7yEBDVOG0So5BEpFWAzmQXx1hDa1z</preKeyPublic>
        <preKeyPublic preKeyId='46'>BUNkKCcRtbEd7o1EGblx44wvMJV6QewbdTJV+N7kOc1w</preKeyPublic>
        <preKeyPublic preKeyId='5'>BeE49/UEL5xuUia/EXMMtygW8EA70wlxuVsyaSVaSyZZ</preKeyPublic>
        <preKeyPublic preKeyId='78'>BZoD1twCzfS9z0yly1udvLrry33B8VQdbuMwEK1FdDpn</preKeyPublic>
        <preKeyPublic preKeyId='27'>BVyZPvlbftfPwXjQzP7GINtvLV3nzrmDY67MJRTRoD80</preKeyPublic>
        <preKeyPublic preKeyId='48'>BQ63DG/HRJOjkNtoxrsLYHHBmqg3+eNAoseHhFRjZWlZ</preKeyPublic>
        <preKeyPublic preKeyId='63'>BTpAqWXwpUgiirW8YWDkP7JtkPz3bX+wx23CGCzAGCRn</preKeyPublic>
        <preKeyPublic preKeyId='55'>BRLMEzJPX3UYbguR8fl9+CKwcYs1Dvys13YH6wVjc6sp</preKeyPublic>
        <preKeyPublic preKeyId='57'>Bb140DTrxtjXGRbXvddQI9CaQvCJZ8obz9gcSzZJzX1B</preKeyPublic>
        <preKeyPublic preKeyId='19'>BQYr4nNs3675UgEg9YDWPNBwoDpYcEOZOnE+6ehM274P</preKeyPublic>
        <preKeyPublic preKeyId='9'>BcwAOg+Sq51mfBpVbIxPesf9UBGpcQzuVKULyd67g/5v</preKeyPublic>
    </prekeys>
</bundle>
"""
        if device_id == 1640101268:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='5'>
        Bb56Sq+3+yqhVs2KorzLccHKbHGO/71akNqS8warobdi
    </signedPreKeyPublic>
    <signedPreKeySignature>
        ZBruXRe59jaJnmX1MGNB8gRHHl1KS8z1pC4jbQ4Os6qdd00bczRK2OXBMDN+W+J3u9c20bYbcretF72ZV38whQ==
    </signedPreKeySignature>
    <identityKey>Bde4XMA5ywmeeVb3ZiNPHvbAoEAwDEz+y/P/hA+3o+8N</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='463'>BWK2z9o7eoiPPqePPbzCoLxZMeRfuUJ4l25R+Z9wzSwS</preKeyPublic>
        <preKeyPublic preKeyId='449'>BaVAihtG93P9eK3ilahF+PGa7fC/GrpSO7BYvFVqaUhK</preKeyPublic>
        <preKeyPublic preKeyId='509'>BcJtsvWC5CDbWI8ftfJkwJ2vjSsPQXwCUH/fSC0HlqFu</preKeyPublic>
        <preKeyPublic preKeyId='460'>BQApNu8TEbKQE7jY/lEHpR2UzmYDXB7exat3qLZ9twAA</preKeyPublic>
        <preKeyPublic preKeyId='489'>BRiPRZUgL0ExeO1WpIX6GeCFCVvOeTFJy4otvwtp1T5V</preKeyPublic>
        <preKeyPublic preKeyId='517'>BfswL34ndNXGcORNOmISCS7WTs8FNyOp2YuNpKYdOGEu</preKeyPublic>
        <preKeyPublic preKeyId='476'>BcCPBF2WuVMaWDwTvf0uQjK0bz4RDgiBJTwFsM0rl+8G</preKeyPublic>
        <preKeyPublic preKeyId='434'>BQEL146VA6SrscGO9/uMyjJBGpMIa+ika4bftn6PGYY9</preKeyPublic>
        <preKeyPublic preKeyId='486'>BTLhrLPwnYpNyZ05qwxBkW+hp+fg7v/Ph6kEuIfWFX4R</preKeyPublic>
        <preKeyPublic preKeyId='499'>BYeswOrQfDwYsH0huUYKUYJpaatCFfICil9WO17H4B8e</preKeyPublic>
        <preKeyPublic preKeyId='480'>BaD+RmbkZVtcyF1jictmSzbyTdClIXErA1kTYb3NChQF</preKeyPublic>
        <preKeyPublic preKeyId='477'>BRDARNZhFV5myUenoQbC8s+/lwbfZlUQV0Jtdy8DOuk3</preKeyPublic>
        <preKeyPublic preKeyId='514'>BetT8bN9JKHzsFadSO/D2Ppz5VBlREmF91U0BV5Nb15h</preKeyPublic>
        <preKeyPublic preKeyId='442'>BUP0QAAnoLqe2j3G6X891zwTrdX//YkvjA4PF4HRUHVD</preKeyPublic>
        <preKeyPublic preKeyId='447'>BU6E0L+F7i09im6deOKTjo5wpPeyWOAZTgotXWoZ/u5I</preKeyPublic>
        <preKeyPublic preKeyId='438'>BchuAomJkoswYxo6st1pcz6S5pLvjyo7eAqRV3xN+dwT</preKeyPublic>
        <preKeyPublic preKeyId='503'>BaNV93ir+Cr+Mkv5NmHt7wLQq72VdkJ1WDpWoZUUb/0G</preKeyPublic>
        <preKeyPublic preKeyId='452'>BWFxLG6YIagt03fJfXkyxEvmQZoAR58Th/W7+t7GVS9e</preKeyPublic>
        <preKeyPublic preKeyId='507'>BXpKOKkKyDvctVAMjgl5wNmpD04lTSpbxiwr3ydciSJg</preKeyPublic>
        <preKeyPublic preKeyId='428'>Bbotp439tQwoMYc2MBrgxNiYdGUUgw2REkkNTWfTYsIp</preKeyPublic>
        <preKeyPublic preKeyId='445'>BaEYKh3TuMs+JBTUrwEgzBb8SPnok0pxAq0wlREMggJ9</preKeyPublic>
        <preKeyPublic preKeyId='429'>BfViS4r8QUPuZ92Xnjlnumsyt6LmCKPTwI4XpAarM10+</preKeyPublic>
        <preKeyPublic preKeyId='500'>BVHCf3qb03dKYruS21pEGlfXEWLiUL5+SNXmBvnMAZE5</preKeyPublic>
        <preKeyPublic preKeyId='505'>Bfvl/UVsK5mPxHtehbAZUMcqc3Bhd2APb/uRh8sZnUBK</preKeyPublic>
        <preKeyPublic preKeyId='504'>BdS+GlNKbZn5F1BVq18MbDgpipmjI/+YMvWM9eU6UG53</preKeyPublic>
        <preKeyPublic preKeyId='468'>BTYVaZFIcaMDrro0dyiVAWIr3VUvgXesPnOVHITNxdNa</preKeyPublic>
        <preKeyPublic preKeyId='474'>BRw3C9LQlZc0zcs4ksDbXcHGgEz7TNhcgHE0PssYH2Qr</preKeyPublic>
        <preKeyPublic preKeyId='485'>BUqEpEFIwblZJcOhw933PyC5WUqdS1R5B2CGkEPJR49i</preKeyPublic>
        <preKeyPublic preKeyId='482'>BepCVroeFiIxTZKAiQ1YQOTs1YMgV4FSJLWoKN6iERpe</preKeyPublic>
        <preKeyPublic preKeyId='516'>BRx1VoevFsqtTEtuA6O6hKwvEmvnHgyq/SUjRKo0NkFa</preKeyPublic>
        <preKeyPublic preKeyId='512'>BTGr+wwmMR824jHfzaIm7QYBTuU6SYy5e9cjJ+BxLOhR</preKeyPublic>
        <preKeyPublic preKeyId='472'>BbxtB9LuDRhjDaHmXhTNmeDvOqDa5LecE/YypRRkSZYU</preKeyPublic>
        <preKeyPublic preKeyId='470'>BX8+g3Way7E29BRFz4AhX7zVTMmLmAGIw5fGEq/7k+t/</preKeyPublic>
        <preKeyPublic preKeyId='492'>BYUs3HM0BL3V5fKS57z/NXUXe9MgSJAWJq+bAXSgPTxG</preKeyPublic>
        <preKeyPublic preKeyId='418'>BQM6NHtn/tthurMYQuGWG47cOvzRu+u1VIJ7iFGJBb95</preKeyPublic>
        <preKeyPublic preKeyId='457'>BcfQ4j2IRxRps6hP8fCMFQYW3C36dc56F/7YzpCXSCh6</preKeyPublic>
        <preKeyPublic preKeyId='423'>BSxXkKFdQtm1ii3YlsinZypzJ7cJv1tZzVr9hA4gxug1</preKeyPublic>
        <preKeyPublic preKeyId='471'>BZIbdhIWo0VtCrMn30p/MEKemH0V6AXTCubOLUVopNpQ</preKeyPublic>
        <preKeyPublic preKeyId='501'>BVKa3XDyKRNLi4x5ih/CSbVJa6YSZsjft0q5sVci1pVh</preKeyPublic>
        <preKeyPublic preKeyId='455'>BeNrEY79crEOjGRX7ThfNthxOqoTEWranqV6At0DiscZ</preKeyPublic>
        <preKeyPublic preKeyId='496'>BVAiqJt5J03YGzRuLr/fJMosVcSPqvW9NXBN0JDP9P4S</preKeyPublic>
        <preKeyPublic preKeyId='417'>BagT6dbgOyYUEcepv5hzKH+OFODbbXRsEFqVJHip8SdF</preKeyPublic>
        <preKeyPublic preKeyId='510'>BbOqQoSv3ThdpQA7XRdc6U5QIruSG67M81a0hJYS6EUN</preKeyPublic>
        <preKeyPublic preKeyId='433'>BRFn8rFbcOgTYEuRAfQfyL4/AkayIBnRbzBhCA/J99ci</preKeyPublic>
        <preKeyPublic preKeyId='473'>BSZsGyYkh84SeImLxLktftlgH2Nv01UyrOYv8aIuGupy</preKeyPublic>
        <preKeyPublic preKeyId='454'>BTVEMR+vnK/m60phhO61gXXTCY2935JDdfOBplihQVk6</preKeyPublic>
        <preKeyPublic preKeyId='422'>BeIA0FftPWXytksh+ceDDiM+nXUDyrcPdirYX/ZpVrIE</preKeyPublic>
        <preKeyPublic preKeyId='427'>BUzyxMd0RKYryw8OSYqAh26Z2yzNNvLEryw6AM+R06Bt</preKeyPublic>
        <preKeyPublic preKeyId='508'>BRyctszECRnuOay1PkY4V/4DYQdDYgAEu6eMi5h03b5t</preKeyPublic>
        <preKeyPublic preKeyId='448'>BeY8hWLcFCH78EJ/KsyzrmjfAO+iZC7QH9CKnxwusRcg</preKeyPublic>
        <preKeyPublic preKeyId='450'>BSwyemL+xJLGb7xBEDL7EJ002PgthmMfM21zqKdJJAlI</preKeyPublic>
        <preKeyPublic preKeyId='424'>BZnH3XzFF42xmY9FPwnAJNATzS0ypQPmYjr1itUiBAl5</preKeyPublic>
        <preKeyPublic preKeyId='444'>BaKgrGCzpI0gyByNdCMOR3+QJ8ho0epveYAcIKf+h5Fl</preKeyPublic>
        <preKeyPublic preKeyId='440'>BUYxDh2eVBGNSVGPi1rqguBgiTbVLGIqcbZLMKhSBosY</preKeyPublic>
        <preKeyPublic preKeyId='458'>BTX9ihvjiLtqtqsPpwNmK/0z0/NfT1Mi8bkQndrDjudr</preKeyPublic>
        <preKeyPublic preKeyId='425'>BQIADpCQ3GSQdNThuHSfhaAqQKIOoZAO50npUoqMeEAt</preKeyPublic>
        <preKeyPublic preKeyId='420'>BVG2C59A4iDmWflKrjfuthEJp03g3vv17/Y5GywJ5Sta</preKeyPublic>
        <preKeyPublic preKeyId='483'>BUvCubbhvmkI9aInc/HpRxh0JBgny15i21Bm7o+15Zko</preKeyPublic>
        <preKeyPublic preKeyId='478'>BT4i4/nCuG+mcChLYG4XHiyK6zY/8C94RPjfMC5jpkVL</preKeyPublic>
        <preKeyPublic preKeyId='456'>BcfncWSJnslQPpLJcwcmCwIfY/052+H0jNA5TTEJmaB3</preKeyPublic>
        <preKeyPublic preKeyId='419'>BScz2nrTbgg0LCHByDcMlzT1lIYtgkDNfD6ZT6YnV+wC</preKeyPublic>
        <preKeyPublic preKeyId='466'>BSF0AZSDAI8vlm4EHD/qiaHJScU9Q8p88/nd+sQ03/Mm</preKeyPublic>
        <preKeyPublic preKeyId='495'>BY3jsGNuCNTTK1XlzcWAoMOLsaxPrV2NoEug1XF8wLMs</preKeyPublic>
        <preKeyPublic preKeyId='467'>BcJACc93pwJWqsLXL3D8l6Ma++8eW/FKD6cH8fvodN8g</preKeyPublic>
        <preKeyPublic preKeyId='493'>BV+3I1S23G8kBeY3EdWMQra4+W62ZHIL1SNkVg//zNN0</preKeyPublic>
        <preKeyPublic preKeyId='481'>BYonMs9HjGunG+aoJ9/kzF+jfP35sAESyFZqguHxgocK</preKeyPublic>
        <preKeyPublic preKeyId='446'>BQo4EdHUzSqgXinLN2JIy5982u74bImnQqyq4iPHRjAP</preKeyPublic>
        <preKeyPublic preKeyId='479'>BcCKbmrZCC8MtHfv4QcqVAT4I0awwvj5ztd7R3Twxmhs</preKeyPublic>
        <preKeyPublic preKeyId='511'>BUGspg+1nywNKdFoLD7vrOL0Q1wFZp9Nq7bj4GvAGY5b</preKeyPublic>
        <preKeyPublic preKeyId='475'>BdiE4QoeQSsJnBrWAux7Li7lVtbsbg1B0O5byx9BdpwN</preKeyPublic>
        <preKeyPublic preKeyId='506'>Bez+HwxYfIpDjYO1lcXOAXn3Tn5Tv3/a7bW4RKvfm0Ya</preKeyPublic>
        <preKeyPublic preKeyId='513'>BcGNe3/S3yBzVejHaXvUZfx9q2XTYyfzVykIttpHpm9w</preKeyPublic>
        <preKeyPublic preKeyId='484'>BScmDCFbHsTi+FNDVXoEplndbI0W0QSWEBC8Lxax2mhj</preKeyPublic>
        <preKeyPublic preKeyId='453'>BezT+Fy/cUE+h9ACZ/Qrm2VpR0yYv2VBKblbhkvk8nF0</preKeyPublic>
        <preKeyPublic preKeyId='431'>BfdrOSuiQCa2BM11u0tapbCpvNdBi56vb4PDE0HBm1V9</preKeyPublic>
        <preKeyPublic preKeyId='443'>BSr4hVJhATSMOCNqRDhlUTkBtvOIzTwaRpvIbaK9w95u</preKeyPublic>
        <preKeyPublic preKeyId='494'>BTIYb0zqWR9T0rMRd0YKAZ3grGvzRW5uC6M9wlPSJmkE</preKeyPublic>
        <preKeyPublic preKeyId='498'>BQcC5nwADNEQfDGnWXiZ8px1pjbRKgQIJG3e01u0e2x/</preKeyPublic>
        <preKeyPublic preKeyId='426'>Bbx+xzlTIsCN4u/I9BgbPDWBG/em3x/ZEf6k/13lEAIV</preKeyPublic>
        <preKeyPublic preKeyId='435'>BR7ptY4eatCXMvczer9gNuIrnsLmT8vcokNHgiwrTTI/</preKeyPublic>
        <preKeyPublic preKeyId='488'>BeZPXM7mBc8F+4yfIwJkACr3RibL0ottg35KUvGWbDQl</preKeyPublic>
        <preKeyPublic preKeyId='430'>BQc4oKuHKUqv5VrlRobpWchd7esue4oxYAKG7mVUSjV5</preKeyPublic>
        <preKeyPublic preKeyId='469'>BdRklhvqykenRkdNJskXVyQfVcuzlfMkp3IyWNb2+4Ii</preKeyPublic>
        <preKeyPublic preKeyId='421'>BX3xrMlXM/vuDiCzoAgsg6BQIJt3hS/URsQN4a/A7rE4</preKeyPublic>
        <preKeyPublic preKeyId='464'>BSzdRP2A8PzsSnXWHLLpqeYt1l+qE7AI38ZIZFt56hx8</preKeyPublic>
        <preKeyPublic preKeyId='497'>BfyKEDl7tUD3rpqMf+eDCHeT0Tu2e86RiZdkKOx4Hytv</preKeyPublic>
        <preKeyPublic preKeyId='502'>BdKft+OrKiSnIkFm8AbCjovF/Eyfhzb/990KHCisn9ca</preKeyPublic>
        <preKeyPublic preKeyId='437'>BZKKgDS1tdSYfYmR7vhRQ3ulAeAu7X3NSQSmtz5LZZIA</preKeyPublic>
        <preKeyPublic preKeyId='491'>BcVleaMs0nGfkpSF02K6dnqpbN28fStfZkHGnekXNZQj</preKeyPublic>
        <preKeyPublic preKeyId='441'>Bfx7N1YdH7B56T3lp67VsXlnDGT3PS/QM6GaO8xMrq0S</preKeyPublic>
        <preKeyPublic preKeyId='432'>BTFwMUxBL1lSrGX+soHOVKQWgj6fYpTxj+zu+vhF5bwf</preKeyPublic>
        <preKeyPublic preKeyId='459'>Beter2x8iA9bjf/PhWnzWFADs3Cbm8qd7rW4L+zQ8cJ5</preKeyPublic>
        <preKeyPublic preKeyId='436'>Be98IjNkHscgzWplcnRriGOenF9ixK3JH9Sv4+NiwVYn</preKeyPublic>
        <preKeyPublic preKeyId='515'>BRN7usPRXCWtFFFtOcO8TPhROLgyv8RFLV4zLwkkCoc2</preKeyPublic>
        <preKeyPublic preKeyId='487'>BR0Dvej8k/3FBtupggkt4pxCGeEwUPSVgdpGasraCW84</preKeyPublic>
        <preKeyPublic preKeyId='490'>BYU6NvsRzIvHnQVd+BDj0xZBm0aQsUL1rBHBo6xrdhAi</preKeyPublic>
        <preKeyPublic preKeyId='439'>BZ4OnZ35ozDXD97n7/278KrulqufHtXMczoq2YeWDLY8</preKeyPublic>
        <preKeyPublic preKeyId='461'>BbtSmd6zrejeqN3MLxUQdms7/t5ZOegJh8DRhvzXsBJR</preKeyPublic>
        <preKeyPublic preKeyId='451'>BVJQyaXJyUWQfEoNLB2WFV8VuCGcTw4RQUy1zVdEmWtq</preKeyPublic>
        <preKeyPublic preKeyId='465'>BfiGZKfAE0HYZsVHSQhBYPyTJBsyDIt8ZSb6RUYCsH4L</preKeyPublic>
    </prekeys>
</bundle>
"""
        if device_id == 276148623:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='1'>
        BRAGEATm/N85GPxpFLiCgpaWpJrSFHDruKDx434wF21r
    </signedPreKeyPublic>
    <signedPreKeySignature>
        5uTepMjiZq5CIoupPnxj97kB3foXRAE7aGknuxk55kFp2F6HbQbMd6hEDwupsnEAi9AggdCuBFZI6qli3kG5DQ==
    </signedPreKeySignature>
    <identityKey>BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRi</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='1'>BeNUu3UjUSlcnRyfUkH+AXU8zhWqSTDqGQ7cE8I8EbdF</preKeyPublic>
        <preKeyPublic preKeyId='2'>BQpUO6qvTUX+BUiwTELlfat9uZRNrhDCGU9+MLLzCjMP</preKeyPublic>
        <preKeyPublic preKeyId='3'>BfMkSBbSlTIdTwcNMdf2rZR04Re5haYiYCx3rFKfaSFF</preKeyPublic>
        <preKeyPublic preKeyId='4'>BbSUOCsNbrFQo9VXldeCsLyVhovWgiADLR5zOZWKGdB/</preKeyPublic>
        <preKeyPublic preKeyId='5'>BW+x2zpeL+X90liEmkdUMUzFlz4aTISqnmm30s9WYek4</preKeyPublic>
        <preKeyPublic preKeyId='6'>BRYztz0w5QxwFie1lpjMMjXmaRqvsqMmHqTn0Rr+Ayg7</preKeyPublic>
        <preKeyPublic preKeyId='7'>BT0/rq/rnRMGccU82vaHYuP+jMbL7G1TkXzz1uS+kfgH</preKeyPublic>
        <preKeyPublic preKeyId='8'>Beg51acq0jJlwc8ucfwkRd8TdxTNhYHcUjnYKVr+I/YX</preKeyPublic>
        <preKeyPublic preKeyId='9'>BUZi2IRqn5yg1sFd+cIWiLFe6aQk+jlNNL1ZWtBHBncS</preKeyPublic>
        <preKeyPublic preKeyId='10'>BRTxzAUuEun1acKFXGpOaWXOubrsKIQjc+hsInkTkBpI</preKeyPublic>
        <preKeyPublic preKeyId='11'>BRylplj8Xs34MMczt1S00k967u2KAen5jDcmb2h4uR4d</preKeyPublic>
        <preKeyPublic preKeyId='12'>BZT3WVM5XoqlJ6cdun0bSjxh1BLHcM/ZoUZ8oosbke5o</preKeyPublic>
        <preKeyPublic preKeyId='13'>BaqxiN7Zh60RLF1A8qqG03cL8ozGbQYN5EO3Kzz/PFVk</preKeyPublic>
        <preKeyPublic preKeyId='14'>BStRyzS7QNPqluePDFfu6RtWLrJ2YFp9Uya3iAFBTJFt</preKeyPublic>
        <preKeyPublic preKeyId='15'>BZtRhQV5NttmS5YPgxdMkEe6cIzmObhT6V5IWvZ3G0RR</preKeyPublic>
        <preKeyPublic preKeyId='16'>BSCMXlnQ4+OO8veU+jH3t8ln/vNUiKi/6qKnPdTV1aE2</preKeyPublic>
        <preKeyPublic preKeyId='17'>BR77hF5ZDEj/y7aBxLUnPb7X1b059a6bwVUmnxjCllRB</preKeyPublic>
        <preKeyPublic preKeyId='18'>BfZxNiHoLDXej5/yz5g3jog/tKEZuafY7YDmRC6aqEBX</preKeyPublic>
        <preKeyPublic preKeyId='19'>BVIUxvkXDDS9rJPYfCuCK5rcLnlgwlyJ1mlHHFxnRd5i</preKeyPublic>
        <preKeyPublic preKeyId='20'>Bb/cqiENgkM3qTMMPdYae4MKqdo5MJPn1CMkcS9BWJIo</preKeyPublic>
        <preKeyPublic preKeyId='21'>BYR+F+Wk3OUpg3j1Vw3W1mW+Pi7YVFrp0AZQHpxDL7wS</preKeyPublic>
        <preKeyPublic preKeyId='22'>BYMBgoPcdJDcoSpcpLZICLp7GSUxxQfO9edYkFLr9R5C</preKeyPublic>
        <preKeyPublic preKeyId='23'>BbN2UDSLM2OV93VDi8XNRTK8qQts2K+zYVvo0MagHOkV</preKeyPublic>
        <preKeyPublic preKeyId='24'>BWl/GRV61zaQGFa8TPZ4lGa69KYHeAm8v4bT2JtwIEUk</preKeyPublic>
        <preKeyPublic preKeyId='25'>BcUsriw4cHqRtUNNjjHR4ZmxLCIbEULJWrHVpcYIZTtE</preKeyPublic>
        <preKeyPublic preKeyId='26'>BR3q2WjbX3Z6lo1BF3iy9myq/QYETjuf++2Cty8V8oBV</preKeyPublic>
        <preKeyPublic preKeyId='27'>BSbvecMPdbQVT+rC3Qr2o7EKbCm2OUcaWCu6hgV57ZcQ</preKeyPublic>
        <preKeyPublic preKeyId='28'>BVNpuybsVJUsuVOna46JhAyTYHXGco2S10d8QCDN8zRK</preKeyPublic>
        <preKeyPublic preKeyId='29'>Ba4fghT/Qrnssq7I2rZckM8RDEiSSwt/MJ2fb+Bk4kUD</preKeyPublic>
        <preKeyPublic preKeyId='30'>BQKv8yBFVq33nTujzSKdGLL2bnnuON9Jwj/v2gzaC85f</preKeyPublic>
        <preKeyPublic preKeyId='31'>BXUdOlqWGhUDyaTJ97VBk8Y4/d8ykZzX64pOyJ6SeyNj</preKeyPublic>
        <preKeyPublic preKeyId='32'>BcyUwhkNbtO0M6jSP5TtYdxZtlUnlDefo6Tns0EvVM0j</preKeyPublic>
        <preKeyPublic preKeyId='33'>BQx8X6QcFNmX846SgaxbPIONbRCntHLlYOYl/3Hc+Adh</preKeyPublic>
        <preKeyPublic preKeyId='34'>BfjW0RaCYtVNUO6zovrYQhcdfRfXJOSBWyMa9CwPxbJe</preKeyPublic>
        <preKeyPublic preKeyId='35'>BQdpFShDybBP3kUOC/FWSOWPIRdg3vOE3YyA2zeUYMtB</preKeyPublic>
        <preKeyPublic preKeyId='36'>BXz1VMNC3ob30TqW6VkqzlXHpOhRVl5n3wboUrE08GlX</preKeyPublic>
        <preKeyPublic preKeyId='37'>BTCXbdMKy6VRG3ZZtMK5MWRQsAFlHgNgvA3ku6JBA8px</preKeyPublic>
        <preKeyPublic preKeyId='38'>BcTNImc2XYdWMy6shwzXWcNJJIXU8aTs7KOkCswEhiBd</preKeyPublic>
        <preKeyPublic preKeyId='39'>BZMzbKphdJPJ+3FRUUdRnbva8jy+ZKgjOl1Hfma6oSQd</preKeyPublic>
        <preKeyPublic preKeyId='40'>BYBE78MQzieoTs64YZWQ8fzqP3iT8u3fqZgtqk2LciNF</preKeyPublic>
        <preKeyPublic preKeyId='41'>Ba7KuOBFR7QPduIU6jQHTsiRBAQ3cVY8OvcikUniGQMY</preKeyPublic>
        <preKeyPublic preKeyId='42'>BaGlPxlDP/KC31818WH9rC86Z3XbD+/t3uCnGe5TXzQr</preKeyPublic>
        <preKeyPublic preKeyId='43'>BWJl4rP1ER9/EoMQ2YVXSycwas0JdrKK6dxeU/zJYbMo</preKeyPublic>
        <preKeyPublic preKeyId='44'>BcllpKnE7PfMTJEjkz7zYRpQx+9x+1xAnDlj/2l4GM47</preKeyPublic>
        <preKeyPublic preKeyId='45'>BdYPMqKXpFChvRDRAB4/xhdQNojNBZ4vIcT/G7U8d69E</preKeyPublic>
        <preKeyPublic preKeyId='46'>BWrZ3NTPnt3NUWN0SdebI7vCs0s2KFZOzRkQsZYOylpW</preKeyPublic>
        <preKeyPublic preKeyId='47'>BV/XANJL9ny/o2LOsbzsk3AkY4vcgrw8vILO1VCSvjlf</preKeyPublic>
        <preKeyPublic preKeyId='48'>BXm3ikSSxXsuJvJUqfF0xI6wWedWm0GHfmNEsXEZVvBd</preKeyPublic>
        <preKeyPublic preKeyId='49'>Be0ap8fo+FsO4mQEXFQFkD1eBY8hn21X6MY7OYpr6ch5</preKeyPublic>
        <preKeyPublic preKeyId='50'>BeLyp2owZXjKfHjkGdUDJBnXlzLnsGGlybcfjZK2hgwf</preKeyPublic>
        <preKeyPublic preKeyId='51'>BZ23o37XKOcNbWFO9RAgKApUtjJnJ8uy/+eXN5e79QMz</preKeyPublic>
        <preKeyPublic preKeyId='52'>BSnxJFmNUIiADzMSWcmGyzuCPOf5DB+9TNKikdDUMFp+</preKeyPublic>
        <preKeyPublic preKeyId='53'>BfbBErK/GhleyRbxaWBCLDKMK92Tz8QKFKB35ukP1oo4</preKeyPublic>
        <preKeyPublic preKeyId='54'>BfTKPbhF1MIpSdHtzDPDdyRAfFh6Fq0DUo+i8B2ycn1u</preKeyPublic>
        <preKeyPublic preKeyId='55'>BZxaIDWHgP4yr+ylXB6zWtl+Q3QOFHPyOWgDUpH/c5sy</preKeyPublic>
        <preKeyPublic preKeyId='56'>BV0vs8RDwi0/TwzaObptTh1MUhxiPNT5mGsl9wYyQZgU</preKeyPublic>
        <preKeyPublic preKeyId='57'>Bc/lTbzPSyuHM3AG7vyJTrmrlaqcg4PCYO6/JlRCZ7B/</preKeyPublic>
        <preKeyPublic preKeyId='58'>BU0sBPXnGKu/mR+AKfcH93W4JAWBsYQ+D8OSrDqpY9dc</preKeyPublic>
        <preKeyPublic preKeyId='59'>BdkUf+bIuAaKyIzfdBnv6Lvuscp66CFR4MO7DL0DMWIN</preKeyPublic>
        <preKeyPublic preKeyId='60'>Bci1vng1YyrixRpKc8+k0DC4+RkZSprAnuf2csszZvNn</preKeyPublic>
        <preKeyPublic preKeyId='61'>BepyhL889rXiIJtDuXZquOYbUWZ7B30MWFjm9UzPJ8YC</preKeyPublic>
        <preKeyPublic preKeyId='62'>BVD7jSVyIBbUatnDXXp54dgP0uolhp7TapZyRqpXfAoC</preKeyPublic>
        <preKeyPublic preKeyId='63'>BfI+XvLtTeQGPOu1uJ+aErV+Wo+aCyn5hP0QkOhrrUBQ</preKeyPublic>
        <preKeyPublic preKeyId='64'>BecoehyAcuboPwRDfw94K5K444F59d4qzt6Wyx93veJg</preKeyPublic>
        <preKeyPublic preKeyId='65'>BdmiCK+mkpB4HygvdQmWhyzD36xo0L1/2CI4VgjIgmIS</preKeyPublic>
        <preKeyPublic preKeyId='66'>BQO0CyWILiZWOukCH6ijdT+3J8QzzFmnhG6cOt/HQdlK</preKeyPublic>
        <preKeyPublic preKeyId='67'>BRVIV67Pu+n3giWaTJyiMeFhsacWgkXnD2Hw0pK2Qtxp</preKeyPublic>
        <preKeyPublic preKeyId='68'>BXFdBjikeRo/6zulwtv6lktEC2LbDQ8uI+3BbBzo+7pr</preKeyPublic>
        <preKeyPublic preKeyId='69'>BYQVIyRVk3FgcqeRIN9cHVpzD57slg+f+TlnfCrzsRYn</preKeyPublic>
        <preKeyPublic preKeyId='70'>BTpxZlqpiHAinW9C8ZGX3Snk/h48qbPinQBXTOUJMpc2</preKeyPublic>
        <preKeyPublic preKeyId='71'>BWGsEycDGXveLJREdAr/ROtgU93QXZpgOcqiEXyJURk8</preKeyPublic>
        <preKeyPublic preKeyId='72'>BSNCaLrIpN2D4LPi7Dqz4TTQ/2V+0mEmcb43+rg5jgcI</preKeyPublic>
        <preKeyPublic preKeyId='73'>BUSETpJyknJlGW3VneeNkCl51PGEPh2c8lBHta9A7RRo</preKeyPublic>
        <preKeyPublic preKeyId='74'>BfjUVOiWTBuhXhNerzD5fK+hltUDxTcOYdDOnijfqTI7</preKeyPublic>
        <preKeyPublic preKeyId='75'>BVk3Mu87agRlpOTrt/5HgDUj8yHrbcflzHbglRnYeUA8</preKeyPublic>
        <preKeyPublic preKeyId='76'>BZpwdiMfH81PeP8evIyHvg5Ip6qAbv6BOwKRZJAPs7EE</preKeyPublic>
        <preKeyPublic preKeyId='77'>BcAMbutxqpL/88ooTljpGydm7iWLnuspgHnC7RLLYBA0</preKeyPublic>
        <preKeyPublic preKeyId='78'>BQAT72kMwlfuDzfHEHDzrJrMzwZoeQBTTBqMKggm9fcU</preKeyPublic>
        <preKeyPublic preKeyId='79'>BXLO9o+/gOHgjQeQJJENVTvrvl7OGWQV9f+4qWtjQIYX</preKeyPublic>
        <preKeyPublic preKeyId='80'>BW5AxwOV8HASiyG7bVynNfu8co0edlbYXk5vsA756thT</preKeyPublic>
        <preKeyPublic preKeyId='81'>BXCbOp5bdOS10DcEYJtnL80VUTtLa4auu4MT1d3zcgcF</preKeyPublic>
        <preKeyPublic preKeyId='82'>BdqYu32g1p624CdlvSkjXtkE4fpnGGGeFw+9iN0vwiU8</preKeyPublic>
        <preKeyPublic preKeyId='83'>BQ/Z539ezHZPN8DJ95+rw2Su6rsUfX/23WRn2aXj5a9C</preKeyPublic>
        <preKeyPublic preKeyId='84'>BdZZCvYLt8VMdz0pgFnztPkg8c+2U+q7O6nG6j5zfEYU</preKeyPublic>
        <preKeyPublic preKeyId='85'>BWCY5GBh+sKpGiRvY+CD/aSEn4ZiR5CBgQ/yjXLwLiE1</preKeyPublic>
        <preKeyPublic preKeyId='86'>BUc+4IUa2tz72v9Q8PIIIaQPA5OHGddWg4tyZaSzlb4A</preKeyPublic>
        <preKeyPublic preKeyId='87'>Ba+/2o3pn/ReFDZv/CwlyAyIm4XzGy3dbNiWC1fH4RAc</preKeyPublic>
        <preKeyPublic preKeyId='88'>Bcd5yMvliivujGUH8mrfQLcn6suaIC0/G3VpgCVuYIxS</preKeyPublic>
        <preKeyPublic preKeyId='89'>BSenUqjmX6C8qEnUbhTDcZBsVn2wIM9td7d1yOnDKwMj</preKeyPublic>
        <preKeyPublic preKeyId='90'>BVhf/CuuKK31+afyuffTWpbOE2yFs18FJg7nJEK6/g4M</preKeyPublic>
        <preKeyPublic preKeyId='91'>BWP6BfEVPKUnw42y2MokNLqDi4crA1KMig+phJakt0lG</preKeyPublic>
        <preKeyPublic preKeyId='92'>BRLcR06Zhu6hVYm9NL9dMooioAcXk/fojNRmLB55IYJ6</preKeyPublic>
        <preKeyPublic preKeyId='93'>BZpvIK1rq/QRQavy0PrGAMRMTw8QLbgiA0COygHpZXlL</preKeyPublic>
        <preKeyPublic preKeyId='94'>BWuMSTOhelHHvoU9Iug4x7ZGKLnrPtYOc0x4A+0EndU2</preKeyPublic>
        <preKeyPublic preKeyId='95'>BfypeD3uf4UocSuovxbYxisqE+IqcfC0K+QTKxYHDaA6</preKeyPublic>
        <preKeyPublic preKeyId='96'>BQrcNaoGNi5wlP1NhILDsxWXxVlEU+NWdgv9fUdcMEMr</preKeyPublic>
        <preKeyPublic preKeyId='97'>BaFNZgkleACdsIpPizYT2u5HyXT29oWvGBLGrc+NM7xm</preKeyPublic>
        <preKeyPublic preKeyId='98'>BQZHc4z/LzZDdjSdfgLdWn/NmdwrHDiY76pg49LdGHZL</preKeyPublic>
        <preKeyPublic preKeyId='99'>BZ2Uv/gveWX6pvdszKM6PcpNuE0mlIdFc0MKRtIOmCID</preKeyPublic>
        <preKeyPublic preKeyId='100'>BXMy2wm7WWIcO6g62PRiixmUGIjvQN9GgyQkWuEoCyJ+</preKeyPublic>
    </prekeys>
</bundle>
"""
    if bare_jid == BOB_BARE_JID:
        if device_id == 543990483:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='5'>
        BbOWIjZQvEzC9591NNVkM6pss57nfvmKQLE6mj8RKIcp
    </signedPreKeyPublic>
    <signedPreKeySignature>
        KZQZSjWcEftpwS0KqGVGfMfkr/deodE22yeVT1ecywNyNiwRx/yZSKaiPez61vv3pzmRwc/McT+rLHMWPIEBCw==
    </signedPreKeySignature>
    <identityKey>BV9fZvG3d9VDGN5YesFEza85kVg1fghRgw2VufMB1Dov</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='99'>BdUH1lMcMtT3MeFyk46OkyoFHFoGIBe4vT5P2Q1dmpcE</preKeyPublic>
        <preKeyPublic preKeyId='87'>BSd4/e5aqmjiky1PCaKZ+tO1ifU17KA//bXoIzcByXd9</preKeyPublic>
        <preKeyPublic preKeyId='48'>BRhsy+xFv6TwpDT2Hh20aaIb82jjCXYCv2U6tBR1t/IC</preKeyPublic>
        <preKeyPublic preKeyId='64'>BY0OxkiXMpuVXKYKXbDcJK3UReakwOYPWMEoBg81pdV9</preKeyPublic>
        <preKeyPublic preKeyId='89'>BVWU+umGdgjflq5KvYUQrtYWE+Qjpl5pqOCh9QiHprAM</preKeyPublic>
        <preKeyPublic preKeyId='52'>BW28/3ehfgZu1TGs8KseXb6m4CQDuNimlksAIrtqaj9X</preKeyPublic>
        <preKeyPublic preKeyId='24'>BYm6Y4lChatHHCzHeusRUk8KuggHqFAlfvJr7fv9OP8g</preKeyPublic>
        <preKeyPublic preKeyId='69'>BU004yl3nk3nOOaDLWzJRibjY9RlsEW76axSaTQ6betp</preKeyPublic>
        <preKeyPublic preKeyId='3'>BbvgK0gyEPKX2nstEN11Mr9UIAXU/pzI9QTt8GlS4Fkw</preKeyPublic>
        <preKeyPublic preKeyId='46'>BUcU7Y64IbocezAezZBLV2ztieNh/sjrbJ3KM5fvg3AU</preKeyPublic>
        <preKeyPublic preKeyId='28'>BcDf3dpOQxHuAcgmy2IaVSqmIi30NYhEzZ1ZWbas+FJ6</preKeyPublic>
        <preKeyPublic preKeyId='86'>BWxlSPfigvJj/r58kuabiAigl634IXNyI10+FsHkcfpa</preKeyPublic>
        <preKeyPublic preKeyId='84'>BUN/TL9NHmLnRqIWarqyH1EtOzZd53aB/h/NDu1ZbWla</preKeyPublic>
        <preKeyPublic preKeyId='25'>BXJMrBvdjqpH4a4ncnhn1viubViGN+vR55h/ay+o/3VX</preKeyPublic>
        <preKeyPublic preKeyId='80'>BZ/Lxv670Hul4wIvTxpIRlx4OQQFnyEUmxp0Z8YOfgQk</preKeyPublic>
        <preKeyPublic preKeyId='40'>BVZd+2FNVrNMc2ncspVsMS6wqNIzn9pusM4i07ICXxx5</preKeyPublic>
        <preKeyPublic preKeyId='98'>BSd6MrrzeABo3w1PrJoQv3VypQjiV+DlfJA6H73jpGpx</preKeyPublic>
        <preKeyPublic preKeyId='19'>Bcea60ccGLqbEQ9/WqpYvLgWwuw8xu/ngpK4jTywpNJG</preKeyPublic>
        <preKeyPublic preKeyId='36'>BZg/p4Ow01RFG3tJo7geTcS1Z+C1LiSr8bffKBUabLkl</preKeyPublic>
        <preKeyPublic preKeyId='49'>BUAWVMKBasQX/8oGXTdr3iVOyDnt+49lZAcDLy9bvpQc</preKeyPublic>
        <preKeyPublic preKeyId='63'>BQfhGKf4+YvkE42zK6s02LEmF+9QBMS5Xo5aspfWxfIV</preKeyPublic>
        <preKeyPublic preKeyId='35'>BR4JCCppfdzgSXZisj8Rr7u4eTfEZU1wBckP5wtDzp4h</preKeyPublic>
        <preKeyPublic preKeyId='76'>BXCZeQbR+Y/aDGKcSdyz+XayOkheblWUhCD7aNdDhrph</preKeyPublic>
        <preKeyPublic preKeyId='71'>BSiCPe2NE12boizxS8xkhBEmtjCHcn2qGGh92pMRxfUl</preKeyPublic>
        <preKeyPublic preKeyId='42'>BePdow9Ojyyfx0+QHch9KWMg4jiXwe+ipzJL4dMAP/c3</preKeyPublic>
        <preKeyPublic preKeyId='50'>BfSC/MDHeuYtnubyl1366joTVGBo04YSJeniazs8Xilc</preKeyPublic>
        <preKeyPublic preKeyId='211'>BXbuGHF3V5IXjw8dhQUNd1YSX0w40xMnq9AUVLnfETly</preKeyPublic>
        <preKeyPublic preKeyId='644'>BfRM62Fr/S4hwK14Hbcrkvsq1/fBUAwUxVc1Oy7LZF4e</preKeyPublic>
        <preKeyPublic preKeyId='23'>BcjLGpyawTeNd10EynXk4w6pIdjKBdiREKXQFUKj/sF4</preKeyPublic>
        <preKeyPublic preKeyId='70'>Bdg4LvfnGuHcQ0Db/qaGQkTuqvr5iScnUmoh506RqrdR</preKeyPublic>
        <preKeyPublic preKeyId='779'>BdNn7AbaLYJT85wcPhuX+VQUsJ/h1Qkw3Eo+DJTSxvhU</preKeyPublic>
        <preKeyPublic preKeyId='62'>BU0cWzV5DflJIOJ/313qdOuS88V6dhD+Kmhr3M/ZNGVY</preKeyPublic>
        <preKeyPublic preKeyId='15'>BfsvT0a5VMrMHPa9sTZ+Jqqp0FoEFzm30AYckH5RyllN</preKeyPublic>
        <preKeyPublic preKeyId='1'>BU6UIeA4HRHtcqKPe6+EBSERxIZM1pOtMGExB/KsT5Ee</preKeyPublic>
        <preKeyPublic preKeyId='18'>BbyTnJDkxfs+tuE79Cvhm2xn33m35lSqbCw0/9B6FS49</preKeyPublic>
        <preKeyPublic preKeyId='54'>BekLOgzg5kV0hVZNGO9k0JfTw0ott/vdSG856lCYRHN5</preKeyPublic>
        <preKeyPublic preKeyId='45'>BZ+p6SaN1o5t/nBgv/aoRdGEj+IU/NkKavZxNEUJqaAU</preKeyPublic>
        <preKeyPublic preKeyId='484'>BWaKFsxdB4QPf/az9yKOHtTfhASKCq6mSzoybX64BE8k</preKeyPublic>
        <preKeyPublic preKeyId='56'>BdafEQ9a3aNv/cxNjFpl76uWkgMUfBT9L805DGu8W7xd</preKeyPublic>
        <preKeyPublic preKeyId='10'>BdmhTUPj0iGg8NaSu5aUp84+nN5oEB8UdtXThpoQG+Jm</preKeyPublic>
        <preKeyPublic preKeyId='93'>BSL9zZJQnA0vsuPSVd9C9/dmnjyGm8JqFJBvVuoHDxtf</preKeyPublic>
        <preKeyPublic preKeyId='31'>BbIqEwaSLokaYZAq67rJrPFZqnyDbXFxQ4IyvFB0TL1N</preKeyPublic>
        <preKeyPublic preKeyId='27'>BTSMRMEZz8pdQBBYbJxuF0EhDuOahHuVPUJ3iTEQEN5Y</preKeyPublic>
        <preKeyPublic preKeyId='21'>BT4x6/NlfVs+WVJ/EaImZ6JfJyksFwBKveHeuhmk8GJH</preKeyPublic>
        <preKeyPublic preKeyId='41'>Beaa0SWkkHmEBWvhTVlO+nccsTuOPcI4N2NZhQ2rG6wp</preKeyPublic>
        <preKeyPublic preKeyId='4'>BVW2k/aXWSaqCupn1TOfOdwmcd0weuafGYsiTShg0Mky</preKeyPublic>
        <preKeyPublic preKeyId='83'>BduFbHEfa+LA/vcVCb33CVckt00vTEzsI035vAQ9CDIv</preKeyPublic>
        <preKeyPublic preKeyId='16'>BXXRk9nVCwrXBTvcgdKe/LDsoFubBSKdGvxPMyffXQEj</preKeyPublic>
        <preKeyPublic preKeyId='13'>BclPiYY+63Ge4lDz/IMoAZ2tqAaYHmWQDZQ7G+z1RXEQ</preKeyPublic>
        <preKeyPublic preKeyId='82'>BTIB54ws1tv0oN8oZqqGOHPv3fp33QwY/sxsc4IrUXpq</preKeyPublic>
        <preKeyPublic preKeyId='100'>BX0RymVZrYYe3M3MP0gIae48lWxW1lSHxJOSqEva1Zg0</preKeyPublic>
        <preKeyPublic preKeyId='72'>BUzq6b+ePYiHTIwISbTE9x0NWoLryUv43spd654plWtp</preKeyPublic>
        <preKeyPublic preKeyId='29'>BYHJ7LANbPxzkr8EXtNrtvWR/0+dYT+v0CZ94iUnefd2</preKeyPublic>
        <preKeyPublic preKeyId='37'>Bfe7SS7e/mxCVf3RX4Pj8eaGkzoYWYVKH4JzYJ93oZ47</preKeyPublic>
        <preKeyPublic preKeyId='184'>BSaOGDJtKx/p1aNsBWaM3MSGcYUWVSb5PpWPpMQFZmk6</preKeyPublic>
        <preKeyPublic preKeyId='44'>BUzf1Nt7byH8CgtWwdgS6lxO82ulv8gCKqt/+Rqjnz0c</preKeyPublic>
        <preKeyPublic preKeyId='530'>BcpD+c3kVbWQKLm0o8OIX6upnyxHZMFcO/HQf2Ya438Y</preKeyPublic>
        <preKeyPublic preKeyId='51'>BRY4uiktgcmNitU9xgKaVHN9auA9XTghu3OA9kJZY1xh</preKeyPublic>
        <preKeyPublic preKeyId='96'>BQyYqGwKjOw5jPrHdWE4+KHTEXGmSG1mXmWrEgqdlB84</preKeyPublic>
        <preKeyPublic preKeyId='66'>BbW4GJ6gQciIko2gpQOYme5HBqdf2eBDLcBZLkN+5Pt8</preKeyPublic>
        <preKeyPublic preKeyId='8'>BXb9T0oLFERXPWHGbGwkKuUDfSVhVf39bf4ySQ57X7A7</preKeyPublic>
        <preKeyPublic preKeyId='77'>BVTytuevCA/vCwTe0+kFuxS9/I1p9yh9Ar22pcnO31FC</preKeyPublic>
        <preKeyPublic preKeyId='20'>BTm+wYXqHEQ301gsZiOi7Ha1XhieoV3ESiwjVLMHvuMN</preKeyPublic>
        <preKeyPublic preKeyId='39'>BY24PvHGKHVRAWRCWyas/eIM2gW1q0wR7a/aBP4ILC5u</preKeyPublic>
        <preKeyPublic preKeyId='30'>BWhfsbOCPF1o0bYyBbKHsEGnM9X82HZcjBAS3qGvIZo8</preKeyPublic>
        <preKeyPublic preKeyId='33'>BfAzauzNhgwrfC8lMtwXtW90eV+6NE8yoEzUaqx/6Fdm</preKeyPublic>
        <preKeyPublic preKeyId='88'>BS6Btq4nhR9Mpj++gIrIlNq45qqLV2BBFP21LvtMqE8o</preKeyPublic>
        <preKeyPublic preKeyId='74'>Bdas25Si1B2vqDfHSA1Mp+AnWKeenVYevt374+MXqVAz</preKeyPublic>
        <preKeyPublic preKeyId='85'>Bb6d7JOOEKIMdH3UlHxDawzJvifO+ilQ+B0/kZVNvCta</preKeyPublic>
        <preKeyPublic preKeyId='38'>BUn7bA/RmjsKrQxOdF3LIDXMi91hv88z9Bq/O6+j3a1Z</preKeyPublic>
        <preKeyPublic preKeyId='32'>BfoDHt0MzeQ4CARQqFnLVMKJ71891tcMpcHMcUw3xtIR</preKeyPublic>
        <preKeyPublic preKeyId='26'>Bc7OkcwtCrlHQ/WAXTNYcnbKBebEraHxZXeUgtg4+pE5</preKeyPublic>
        <preKeyPublic preKeyId='60'>BXcNjtsH0WT8iAuNkc1iAwXBPi87O7bAW6NHmxeU4jJh</preKeyPublic>
        <preKeyPublic preKeyId='65'>BZzMqAkJeqkfQEaoc7XYKg47iE+vjBUNFTyIKKKOjBw7</preKeyPublic>
        <preKeyPublic preKeyId='81'>Bd39JzQOzc1s/7U8xrsI/2gcODMxQs7i3qcEa4U4UiJL</preKeyPublic>
        <preKeyPublic preKeyId='73'>BRDSJFBoxMvMj6Wr+TszghiaATp+R++we69kAmUdBjYL</preKeyPublic>
        <preKeyPublic preKeyId='47'>BVg0U8qdTkt/v9aUIX5Q7o9HZ4hgYAyvWOCYK0kZlTVz</preKeyPublic>
        <preKeyPublic preKeyId='7'>BW89cOKGCjJTAWlSoJVDfSqJBxc3l5/BqP/URjbotHJg</preKeyPublic>
        <preKeyPublic preKeyId='55'>BeQ6zjJVJ54/OZZUSNDZLMIBz8xS82PB3UeKlRB0k+Rg</preKeyPublic>
        <preKeyPublic preKeyId='59'>BdpWBkQ51VkY1Sj0ri/aUu2p1ZJUutc236dtDqeHUnda</preKeyPublic>
        <preKeyPublic preKeyId='79'>BbztdUXWLj9egRySZgZJDoGKv+l0nJDNWr9WU9dSduxz</preKeyPublic>
        <preKeyPublic preKeyId='11'>BWlF++9ia1OU6yve69TaDvE2OELMpKgZPt7c+Rs7KixQ</preKeyPublic>
        <preKeyPublic preKeyId='97'>BUZspldcJcf+lDJRUt700dosdwW2RV0Dpr+E+Xvp2gs3</preKeyPublic>
        <preKeyPublic preKeyId='92'>BWaelJEeQCmofbKYvurhIRZDdjQl0cajnhYQ9ybG+Vd8</preKeyPublic>
        <preKeyPublic preKeyId='91'>BXXXPLKU10ks6wusN8tro3VnZwwCtHvl1YcK+sCVcKBk</preKeyPublic>
        <preKeyPublic preKeyId='34'>BbVRx/ebeOTYNdoG91Ji1PqTSeRoVbuH1Bv8ZBLShMxC</preKeyPublic>
        <preKeyPublic preKeyId='9'>BU+ckITkP+NaQ1SD5DnuEz9heymzM9tpkF+nlcqK/NF0</preKeyPublic>
        <preKeyPublic preKeyId='75'>BW1c8yEPuYB2dmzEcfWNijU87/EXFZ7CK+iur58CTN01</preKeyPublic>
        <preKeyPublic preKeyId='68'>BYrAP8PTmZ5qwdyfSFHREwCNF8EN3H0RgulMNMVdE2ML</preKeyPublic>
        <preKeyPublic preKeyId='78'>BaLT5MV8PpMgn9PgINbGbNtwwyDxHTVQn9cOFiJ3gG55</preKeyPublic>
        <preKeyPublic preKeyId='90'>BZudXL4SgOgaNy3jxNRJRha/uOP5K+HNhJyc2PinZ5AW</preKeyPublic>
        <preKeyPublic preKeyId='67'>BV90pZtd8vFJPbur5jUPqcxH8q5d1/UfAAiPXAdL0bwZ</preKeyPublic>
        <preKeyPublic preKeyId='5'>BcdkzzrsfiGYeyS6sz3PulwbqY7qeYaJww14cXCPpCgr</preKeyPublic>
        <preKeyPublic preKeyId='14'>BWfIwOvHBz2R8nMQ4rrMnH3qMaJECkvwfm/GbyS8TGV3</preKeyPublic>
        <preKeyPublic preKeyId='17'>BVVKYndwD44UIkbc5LXGuSPUEFMfIxOg5tk+xY9yrqYU</preKeyPublic>
        <preKeyPublic preKeyId='61'>BcgPiYtZAi3zpwarfuhnBwZn00ZqHN2UtPi0pTI8Lmcq</preKeyPublic>
        <preKeyPublic preKeyId='94'>BZWKiL4YhIcUHGRBFccdlNN0TJiKXjvA/BuBGrEJddwJ</preKeyPublic>
        <preKeyPublic preKeyId='12'>BUrAVLHoU9TkRL1eTgXsDkg+TTDqgujVsHESoHh+LjAo</preKeyPublic>
        <preKeyPublic preKeyId='361'>BWc0Um354R5yMRCUDY0zCFJHvHol5miI5avjQSInVPEB</preKeyPublic>
        <preKeyPublic preKeyId='53'>BZ6pyIV1tbgUoP4VPxleUsCf4KKjLew1mw1Yuvs8c8lJ</preKeyPublic>
    </prekeys>
</bundle>
"""
        if device_id == 1746810996:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='236530489'>
        BSIqQEWVwdu91ACCoprmbClYeoxe980bMALRLpMppVhM
    </signedPreKeyPublic>
    <signedPreKeySignature>
        cCE45vO4tOz83DpJbr7x6nE4zq9yNE7vzDM/NGs3QmxcvEqy+Yy+qTLAQcpdMoovIA1S7pfXRpxQFDan2Dx3iA==
    </signedPreKeySignature>
    <identityKey>BepHj/wMBKXWRnyQLMXRwi104ezCRwf/Cx5GHVowxNsr</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='1184105498'>BdeS3iM2IYfI6FW6NmxNoNH1tpizznkBqEM7yZ8Fkqha</preKeyPublic>
        <preKeyPublic preKeyId='1184105487'>BYgzgffrh7bjs8OrM5HH062xQ2HR4tbDLxaC0MpWAltE</preKeyPublic>
        <preKeyPublic preKeyId='1184105490'>BRQw3DZvYBqwaz4cv5eH0JWJKjsC++wDxtUQx9rAnTUZ</preKeyPublic>
        <preKeyPublic preKeyId='1184105469'>BfT2iwG5HR92CXlc5nhTaic6XU3yQPjUeePy4NMvkBcr</preKeyPublic>
        <preKeyPublic preKeyId='1184105485'>Bee42bjFvAL1SWCrsAeSQ+1su0CcmfN5YmFRT2/eUiNP</preKeyPublic>
        <preKeyPublic preKeyId='1184105500'>BXKChSJQ1XcUq9z24B6zPmhc3gYDVYVFNzrVqg2GLoFO</preKeyPublic>
        <preKeyPublic preKeyId='1184105475'>BZl7uU7U/ucI9s5hYbo40wO/bGZiU4C5P5QV7F2t2BF2</preKeyPublic>
        <preKeyPublic preKeyId='1184105450'>BTYmukG6oy3Rin+TdmID3IBrnruW0pYY4+PG058C27sY</preKeyPublic>
        <preKeyPublic preKeyId='1184105543'>BYxbQUnSlnFmjYzieFvgMdAbJvXT/Tzdus5b2tXu6gV+</preKeyPublic>
        <preKeyPublic preKeyId='1184105522'>Bf+xPcQzME/+WRSatLxxXLfFLYdL+syz8gATrWM3Jf4s</preKeyPublic>
        <preKeyPublic preKeyId='1184105463'>Bcv6rveM7ZnLLkMNFv4tHMmSj0bTPHU6+3UemNFOA7sH</preKeyPublic>
        <preKeyPublic preKeyId='1184105513'>Ba3Igrk4Pj/ul5DU36fc14jDhoVPqyaLNFrydja1kaQE</preKeyPublic>
        <preKeyPublic preKeyId='1184105506'>Bf5lXVwpiq7bNwO7y6rdx8PTyjr/li23CHeW2AiRBwlF</preKeyPublic>
        <preKeyPublic preKeyId='1184105449'>BVZEYyPVjn3zrLDwXB2iTnedhYPY0W4zV3Ap/MxQ3dld</preKeyPublic>
        <preKeyPublic preKeyId='1184105501'>BVfI4hQ8e3R3xScvLfGZPlls+qLr0rZrTClBF0M3pzNi</preKeyPublic>
        <preKeyPublic preKeyId='1184105476'>BTLRS5huia27srw4n4Z8/4Hlx4Qj5e2mgQhB9ajQ2QZ3</preKeyPublic>
        <preKeyPublic preKeyId='1184105470'>Be+Pd3a0EUtmo0UyVjobs/WqC0n7CR4cB0UdCx8LWJZY</preKeyPublic>
        <preKeyPublic preKeyId='1184105523'>BXl07d3087e+EHOK+XVsUIsmpUd08jrG/cFuVydXJaIN</preKeyPublic>
        <preKeyPublic preKeyId='1184105464'>BcSgIGVwwJTaguxhgJX6GDaItVfj3wRkm+wKiHJCK852</preKeyPublic>
        <preKeyPublic preKeyId='1184105514'>BeSvwOiFZlZteGw/59W6COqWlehaaDR7mVrWZp8GyT4Q</preKeyPublic>
        <preKeyPublic preKeyId='1184105527'>BetfqmKs1HQeDpqWzOroOx96/4Cw+bbNtxhrPxz76zR+</preKeyPublic>
        <preKeyPublic preKeyId='1184105544'>BeTOc+rWy7Y1ZuFBHvYVdiNu8d3xkiy3DXv6uItBKscD</preKeyPublic>
        <preKeyPublic preKeyId='1184105486'>BR0sKxpgiI4lKManwcnfGLVZMPWKOXEc0wlKIClDCn4J</preKeyPublic>
        <preKeyPublic preKeyId='1184105538'>BUBC/uq2/RpUSEqtQUB7HEK0QDMrVRoUhJxRHzgBbeph</preKeyPublic>
        <preKeyPublic preKeyId='1184105477'>BRHATuLzWPQaDRMCh+N+S4hP5xrdBbAywBKgwgc/3z5q</preKeyPublic>
        <preKeyPublic preKeyId='1184105452'>Bb62jqkjo8gp6aS1MOVvFF4YSbe5cqgSCCDrZ1+5UpNH</preKeyPublic>
        <preKeyPublic preKeyId='1184105531'>BVGRFjxQp4f70o4jPFAMYSFE4yHT4z3QiZAsMQhX7WJZ</preKeyPublic>
        <preKeyPublic preKeyId='1184105507'>BWOv8a+bU4JaT/T4NM5AjasFL6uRc+yf4fOX5G9UiHdY</preKeyPublic>
        <preKeyPublic preKeyId='1184105455'>Bddybd4FL13TTyYGBq7RmhuZiKJ/JNvv3yAPGS5aPvMN</preKeyPublic>
        <preKeyPublic preKeyId='1184105502'>BRA/FGoJFNAuVx80qvqUJWBye2tLrdLc2hrKD7g+ZNUM</preKeyPublic>
        <preKeyPublic preKeyId='1184105515'>BW4yxpzhPeNcFtxA8/57a23feIStofMsjdIf191xWPYg</preKeyPublic>
        <preKeyPublic preKeyId='1184105525'>BXW4JIq7gmbv9033LHUKN56Btlddvnr1HEyzTw4rls46</preKeyPublic>
        <preKeyPublic preKeyId='1184105471'>BY0Y4dQ5zyLPThaniVpZ6UqXRnsrjIid2YduDHWhRtY8</preKeyPublic>
        <preKeyPublic preKeyId='1184105530'>BcZBjFtti6eCUE0Cme6VIDcBuBs71KEhn3XeOGWTdRRV</preKeyPublic>
        <preKeyPublic preKeyId='1184105465'>BRi7ggC7Q/krYnWsp5tdF1Gwi8pcXFVQkhl8a+cPhaJN</preKeyPublic>
        <preKeyPublic preKeyId='1184105478'>BdCe+y4f/D/kZSSfRTUZnM2xnxdRWAiTjWma+QXEJv1U</preKeyPublic>
        <preKeyPublic preKeyId='1184105529'>Be3e4n88KMcY+YP2XyOgDoNefUSMzRoFHqXdpyFO8AYn</preKeyPublic>
        <preKeyPublic preKeyId='1184105545'>BXZ4xbKCW25dYXAHWGPk/crjL6nMKbc4Z9BxX7KzvUh/</preKeyPublic>
        <preKeyPublic preKeyId='1184105539'>BZeWVUMs2NNAlKGN04VU6iYFbvJ8cqRTlaMXT/Jw9LZh</preKeyPublic>
        <preKeyPublic preKeyId='1184105479'>BQ0lrYleDy4fVTut/6A/BXgUfztuH9sjeRm/x+VENN0t</preKeyPublic>
        <preKeyPublic preKeyId='1184105454'>BdmbRxJwz3fpAU8X1k8+DmcYEQzTqWrMBs98CaEkvvd+</preKeyPublic>
        <preKeyPublic preKeyId='1184105508'>BTu8VItNPmED7S8eVil7NaZ+FrOALuIMrjFZLkWi6+sS</preKeyPublic>
        <preKeyPublic preKeyId='1184105524'>BedBYZwhzNCdcCvz6hgPOYVKiQeJXMLTXpNRJ+iqvc9F</preKeyPublic>
        <preKeyPublic preKeyId='1184105540'>BUlym4ef64S8blV2eS2XZ0QDcvNy3JYfYsvcxh1prM9j</preKeyPublic>
        <preKeyPublic preKeyId='1184105516'>BRs5nFW+lj1PyWJ1AOravpsZMvBDZEF49OCFaXZpFoU6</preKeyPublic>
        <preKeyPublic preKeyId='1184105526'>BSyrv4GMtkpUW67ZNjOEkbppRs1RGUlWwjuk7KZqnwN1</preKeyPublic>
        <preKeyPublic preKeyId='1184105451'>BUjS/qRG5oenQstrc2/GD1C/WoK+pLZQIsIORorfQxlj</preKeyPublic>
        <preKeyPublic preKeyId='1184105472'>BTZcv1jki5KmMFOJrUTE71856cdFvISVzoYnmEiEe/I9</preKeyPublic>
        <preKeyPublic preKeyId='1184105492'>BUPgC06OTretmsd2J3UhXRRQEWuLjBJTJ2QM9W+ANF0u</preKeyPublic>
        <preKeyPublic preKeyId='1184105528'>BQimjEjDopZcdxNDbrw+SEp8gka9IOCxJj918bmXZsNc</preKeyPublic>
        <preKeyPublic preKeyId='1184105466'>BX9hBRvU7YdvJugaJUfrxt3IoMaVU7kMDtJ4/CWEQOBE</preKeyPublic>
        <preKeyPublic preKeyId='1184105517'>BdDAhvWtFcHhN4IMy/P82POfQC0B/3pgSjwpTQZOSZA8</preKeyPublic>
        <preKeyPublic preKeyId='1184105546'>BYuvsV0WVtBZ1F5S3rcxfEG5IV5X5JwG0hKuEB/XP04e</preKeyPublic>
        <preKeyPublic preKeyId='1184105495'>BXnuOkLJxR175Bz2tE6RHbT6F3bSsD5HreaUA6iQuBhd</preKeyPublic>
        <preKeyPublic preKeyId='1184105457'>BXCQHnW4fyTpaRxUIOtytK08zUTt5mitEmBOHNG00Uwu</preKeyPublic>
        <preKeyPublic preKeyId='1184105503'>BdXz7ArVju64rroiiT/AMDN+K4oMZAPMo9b34Wx1qRw1</preKeyPublic>
        <preKeyPublic preKeyId='1184105518'>BTdnomHV49rnJHRurFNKHIoFd2HnhXDrNVvINQtQFS00</preKeyPublic>
        <preKeyPublic preKeyId='1184105509'>BZINz29FoWuRwUOCbONGmfI+KPk0qplv89Ujgg1YPNI/</preKeyPublic>
        <preKeyPublic preKeyId='1184105467'>BQ30VVXtmf3M5eE5l71lb9DbJ1ZQ5KbmRUwHLQrrnIR6</preKeyPublic>
        <preKeyPublic preKeyId='1184105481'>BcpxixO4FVTBI49HC/obpAnLcyJolQAeEl4diYeq2C4T</preKeyPublic>
        <preKeyPublic preKeyId='1184105494'>BQnJ/1a8710WQyfO7O8oMcyyyXPpz1V/FmmYaz0V22YF</preKeyPublic>
        <preKeyPublic preKeyId='1184105510'>BQXtsgMqnf6rZg84ebrpc9C0JTjrgNCgn6D4W/h3zrMd</preKeyPublic>
        <preKeyPublic preKeyId='1184105532'>BbHggiHjlarJBell2H9i2vWg1nTOYz6bCcHkggqr0AAK</preKeyPublic>
        <preKeyPublic preKeyId='1184105491'>BWVybDeXtlYoW/QxEvo2u0uaMA452IqwfCDNlE37T0Bu</preKeyPublic>
        <preKeyPublic preKeyId='1184105541'>Ba6uDxCsQH3GBLTdK+BzFPNKxP2DIK3LTxAB0dcLIM86</preKeyPublic>
        <preKeyPublic preKeyId='1184105482'>Bab0wW9ZZU9XCiTS3duOVWxATx0y0gC6kcUUOVLMSh5T</preKeyPublic>
        <preKeyPublic preKeyId='1184105488'>Bb21httQ9UvDQlW1TdiFcMDf/gjw/7M66T35m+JCkP4e</preKeyPublic>
        <preKeyPublic preKeyId='1184105461'>Be1fs6IXaWKwQr+5/lPMYj2edizRb2LkOYqHNWk4KQ51</preKeyPublic>
        <preKeyPublic preKeyId='1184105473'>Bbq64cxoezAalFK+FzsLkX+7LhDkqroccfd1FkIKNIJ3</preKeyPublic>
        <preKeyPublic preKeyId='1184105533'>BahOHNYksCxZuCgho9Yle/EPa/71DFL1oF89lDn3JSUl</preKeyPublic>
        <preKeyPublic preKeyId='1184105504'>BU7MXugb9PkTXgR2k2dzmsGBixmdkh7g87jzblaTj/Rd</preKeyPublic>
        <preKeyPublic preKeyId='1184105519'>Be0Wa/VTzAFWfbHuhyZ8K6W+5ZLlovWw1RUCK8GyFVMY</preKeyPublic>
        <preKeyPublic preKeyId='1184105489'>BT5MgZJHHgsU45GlB+ja2V4rJxsM4c3HfpNgFL2nK/pr</preKeyPublic>
        <preKeyPublic preKeyId='1184105535'>Bb8RN6U4iy2AaVRc06LEON12MoKNfYVQnV5hC1PlWSo/</preKeyPublic>
        <preKeyPublic preKeyId='1184105547'>BcCmZtCbwdbUyXSb+arXLZXMjYXX64cKWrQ4hQcUnyMV</preKeyPublic>
        <preKeyPublic preKeyId='1184105496'>BcKpdGsW8tIhaLbxbNGrvbifZ8rVW9r9iDhK3itlgnh5</preKeyPublic>
        <preKeyPublic preKeyId='1184105453'>BehtgZp26+7KrUpQcYfL96weMqQ/m/SCzDan2iO7bywt</preKeyPublic>
        <preKeyPublic preKeyId='475983705'>BYRnrETmdM6dXGu6BGVFJp0h0OQ07RtJIDJDfZIbDIFN</preKeyPublic>
        <preKeyPublic preKeyId='1184105520'>BXXTUBRlJCwYV5FGGFFYXWELQGQkMrsI9iVlqwmXcxNp</preKeyPublic>
        <preKeyPublic preKeyId='1184105499'>BefsSk6hYxnNKW4H4zKgiYPu/M3cKKDqlFTnQrLgk/xk</preKeyPublic>
        <preKeyPublic preKeyId='1184105474'>BQG5MI17gts7WvM8b6Iksbpg3zn8UzJ7PbtDvSr/sE5B</preKeyPublic>
        <preKeyPublic preKeyId='1184105459'>BTgCM/7xGwhasIgg1vyrwMGHMdJOPmipPmYwVk+ui8Ri</preKeyPublic>
        <preKeyPublic preKeyId='1184105468'>BeaZf+aUK6sPUNELQ2pat5wdTSFheNu9/GvWyTIaVg4y</preKeyPublic>
        <preKeyPublic preKeyId='1184105483'>BeaCh5gZBHTlvKRPXpDjmZN2clUdzOxNWS6lMV1X1D1y</preKeyPublic>
        <preKeyPublic preKeyId='1184105456'>BaKDUJHq0E281+/hL9oaQxVarnPAixN3WhLzLQX7eDYF</preKeyPublic>
        <preKeyPublic preKeyId='1184105536'>BTSR0FWsdbEZql0Rrcz5gQ+9yx3IBcDP+p3FXHF8u30D</preKeyPublic>
        <preKeyPublic preKeyId='1184105511'>BSGk4+Mv3L0UnQebqM1tzmJG+IqAIqncUFpvCbb07EIT</preKeyPublic>
        <preKeyPublic preKeyId='1184105460'>BWmg5vn6SkbA+I7ZhjHzflTT69qBB2JjRuvXKLELZ+tg</preKeyPublic>
        <preKeyPublic preKeyId='1184105505'>BaDMzuwpU6c16MDxPEUdqC3QGMl/jALZ4srwiYj08Mll</preKeyPublic>
        <preKeyPublic preKeyId='1184105521'>BbpJgifDBc8vVuxMhUnLpsEbVinu/FLMpIvElyw2rMsm</preKeyPublic>
        <preKeyPublic preKeyId='1184105458'>BbuGyNuUnK8497asikw/1x4wOXvV9uyEOpH7L9xrW34R</preKeyPublic>
        <preKeyPublic preKeyId='1184105493'>BVnLskhp6n8Sq6xYgQfv88ftrXp3L8/qI0Th3huERdxM</preKeyPublic>
        <preKeyPublic preKeyId='1184105462'>BWBkBJ/e0g0YwPoZV+2PNB6C+jzGky06UR6krYBYpQhv</preKeyPublic>
        <preKeyPublic preKeyId='1184105548'>BVjSOkiQFcB3GjdpO+a+VSDsuFkkxoj9r29nI5MUhLke</preKeyPublic>
        <preKeyPublic preKeyId='1184105497'>BXy+2T/ToY4oFMZDGI4GkKLaKVyPcuFSZSSJRjoyQNJ+</preKeyPublic>
        <preKeyPublic preKeyId='1184105542'>BZ5MLS9WPSQRzWWO8xFZq1a3m5AwBBp7EhligZth9Kt4</preKeyPublic>
        <preKeyPublic preKeyId='1184105484'>BTTQ4qokkeNIpPx8vJjSIxuv3gU056u5kNVDiZvaOWho</preKeyPublic>
        <preKeyPublic preKeyId='1184105537'>BWd7i7VX5y7jVDguR4Nm9jOJaM5VKMNsPsQtwNyrWqB7</preKeyPublic>
        <preKeyPublic preKeyId='1184105512'>BQU5AU4cjsBsxfJsU2rV/gqp0jQp84PuIHx+eg6hoMU6</preKeyPublic>
        <preKeyPublic preKeyId='1398147212'>BeZ38avZfl4uMJhlopYcyMhcf4ow3arNzYQsc/hIad1x</preKeyPublic>
    </prekeys>
</bundle>
"""
        if device_id == 254614318:
            bundle_xml = """
<bundle xmlns='eu.siacs.conversations.axolotl'>
    <signedPreKeyPublic signedPreKeyId='55'>
        BahCVIP94702SDSK3vqzgZFzDbakztJak9bRIBJo3QBB
    </signedPreKeyPublic>
    <signedPreKeySignature>
        weWEENz4qzj5IADwhP8HMbwTwbjBqog935vBrOlrv6giMPMFP5YfhMGbtMWfkSU0xLlDhU+sqN3rXRxWL9Sejg==
    </signedPreKeySignature>
    <identityKey>Bc84+UOQFYdS1NbOEsA2Qu3UqAqMmJpjAgg04YfdoVdA</identityKey>
    <prekeys>
        <preKeyPublic preKeyId='5914'>BU6z2C1VnNY6YlY/Xx8L4d0gf1OLm98VoTVyuIehkg9g</preKeyPublic>
        <preKeyPublic preKeyId='5888'>BT587ERs6mt9o/OvBPztTmGtHhvssKwQbeJzWT7CbVI3</preKeyPublic>
        <preKeyPublic preKeyId='5911'>BWL21mkN+umhSGqoiT3wiqzm7hEwhvRaJO3X2FODV4Fi</preKeyPublic>
        <preKeyPublic preKeyId='5871'>BQKLia/kduo6y0e3xpW7lKw+a89bsfEhxW7JDRmnnspp</preKeyPublic>
        <preKeyPublic preKeyId='5827'>BV7EikPi3HucFgQG9y7ZJoFZwSkRCIHLoI9axat1B390</preKeyPublic>
        <preKeyPublic preKeyId='5828'>BXytejeBZCGX86r3lD5eEJzHqf2TGkXVwSVJFF5ZIg0r</preKeyPublic>
        <preKeyPublic preKeyId='5905'>BYelEt2QpvfZORWBJztg3ZIvKWom4RaQt77bCHzlUZsF</preKeyPublic>
        <preKeyPublic preKeyId='5891'>BW0yFHkydZGOwCKHkBbbOAR9ApTdUAP9Q+Y+Y3TWDW58</preKeyPublic>
        <preKeyPublic preKeyId='5892'>BfQl4Vii+v9UXAPk6PThOqeeolgR7CMbSwDNz3YmdSdB</preKeyPublic>
        <preKeyPublic preKeyId='5865'>BcyLXbplLaI5jCw4qiFoU2H0ejpiMGHzd/jjcVVlpQkB</preKeyPublic>
        <preKeyPublic preKeyId='5873'>BV/TyPNlOF9muHw58S8fhCWKwkORU37p4xHyTOui1J9n</preKeyPublic>
        <preKeyPublic preKeyId='5919'>BcbgsKhd6kACJS4OQoAkwXhZqfzpwW6fmKFjKEijVS1n</preKeyPublic>
        <preKeyPublic preKeyId='5876'>BVvJ8X0C2NQZO2D/KyZqSurn4wLYqrLWY5lSTvMRLhp8</preKeyPublic>
        <preKeyPublic preKeyId='5920'>Bc82ELMNciP7gHhfJo6rGfOKU3P4SUCri4NaXX8JGgw7</preKeyPublic>
        <preKeyPublic preKeyId='5880'>BR6E07kDtav3dW2L41sR2e+Pqjstaw9NSyYFLznaL3x/</preKeyPublic>
        <preKeyPublic preKeyId='5870'>Be/nygOb7ACvQ3DM4Ox799MG6O1w7A7Yk0VHDMf8ihRm</preKeyPublic>
        <preKeyPublic preKeyId='5872'>BbClj3u+yKDGl7ylJrmYAvZ1LdLhhIZ+96UXpsvgaNwb</preKeyPublic>
        <preKeyPublic preKeyId='5916'>BRmYnRZRmOSmwatzma8DLvwJcwnoE93ghoZqdON4Iowu</preKeyPublic>
        <preKeyPublic preKeyId='5894'>BTvdCCpitLNsBTtO0Lw/9JLI2PFnF2kMkn2f7OVy6hwS</preKeyPublic>
        <preKeyPublic preKeyId='5835'>BStSo8U8Srh2JbR06CINxxKZb/ebgo3xuA0mqfIKGqRM</preKeyPublic>
        <preKeyPublic preKeyId='5860'>Bcterswsb/GOnzjfhoeavITghyKPzJn8QLjCDABwDiQQ</preKeyPublic>
        <preKeyPublic preKeyId='5831'>BYq30USveAfBpysvkrG2t/9MHVsycJ87nIHKYst9XKdo</preKeyPublic>
        <preKeyPublic preKeyId='5895'>BczsVxHWjXmwRAZ2zxsEj4ucEZ1gEGdTMNTKcZhjK4lb</preKeyPublic>
        <preKeyPublic preKeyId='5822'>Bby2NS6Ei0E+M9y8vWlkWxKZJYm32GYvbJ480Ee4TfcI</preKeyPublic>
        <preKeyPublic preKeyId='5837'>BdRVPg4/7UazFO0SzQiwkvzyUUVuwN7o2RFn2HGWJYVX</preKeyPublic>
        <preKeyPublic preKeyId='5868'>Baw3K+FJ5xhaJ1hA5ujeCDP7H2mnT7InkLxpSOea4yc9</preKeyPublic>
        <preKeyPublic preKeyId='5862'>BUf7Jdlw42b9uuDj+VmBxc6ZvXGw3hAShlqvK1ilOLN9</preKeyPublic>
        <preKeyPublic preKeyId='5879'>BXvrCa5Ij0ey+hsH7q+pJHEJ8zhHBZsuMyOdsy9DMjQx</preKeyPublic>
        <preKeyPublic preKeyId='5877'>BfQIIZ4/clxx2AvZU4s/5QqM8z3NU0yPhOgHYsiig1VG</preKeyPublic>
        <preKeyPublic preKeyId='5907'>BfIOwR5NgctvgQ5NT3vO695i+utRvlewY0ZA5gMnA85V</preKeyPublic>
        <preKeyPublic preKeyId='5836'>BTbT8uazo/QLBQWsXptHhH9HFrM3rp5qP/DIzKEK8m46</preKeyPublic>
        <preKeyPublic preKeyId='5838'>BTtpHBLv9SY3qDvhR4pzbvrW0Uyz3q2PzDkjPAQhWxx5</preKeyPublic>
        <preKeyPublic preKeyId='5847'>BZUgtENAVdcbQAVXBHOg/qj0S1v9qciuGJeU8PanQldO</preKeyPublic>
        <preKeyPublic preKeyId='5817'>BRtfVL2S5kmNe/H0KbZQbY9gKjObDTOJd1yl15hExah8</preKeyPublic>
        <preKeyPublic preKeyId='5882'>BWGfn0vLBAy/CXhS1vMrViNtaPfVOCDCIPAmlUkvvwRJ</preKeyPublic>
        <preKeyPublic preKeyId='5898'>BUhF+eNrVQ/YpKqvqJX0MIVQTz35rD0PVfXxnvOCP9UJ</preKeyPublic>
        <preKeyPublic preKeyId='5886'>BSaDq1aggLXs6nf3shArWIbR3Tc4RxUlPUeBKWeTxrsb</preKeyPublic>
        <preKeyPublic preKeyId='5915'>BbsVJQ9Sm/ANoB6Jyp018Uj1AUhTr0r/VlBZ25/GfrJF</preKeyPublic>
        <preKeyPublic preKeyId='5902'>BcBIDvy7GvFaB2L+S32ptB4RC4vCmNzOgMwgsHOR1MVA</preKeyPublic>
        <preKeyPublic preKeyId='5864'>BULity3VwbXyGMcfxTx0CodTBPOMftGFr9JtOlhBY91c</preKeyPublic>
        <preKeyPublic preKeyId='5883'>BcWPS0RqRED/RRzjzxKt4CX9hCQLf4K007H6ttcB4eEZ</preKeyPublic>
        <preKeyPublic preKeyId='5889'>BfjVSWWrXY7NFpIR7FTUPeCH9ueBhzXNTanjMV8Ux4xI</preKeyPublic>
        <preKeyPublic preKeyId='5844'>BTFZwHdSRVNZaAMtOdF3afNorzcW++wX/15xwLw7Hn1N</preKeyPublic>
        <preKeyPublic preKeyId='5846'>Bb33V/GsuNfWkEdB/LmkzqlTgwMNGE/uCi5mTsfjDEkP</preKeyPublic>
        <preKeyPublic preKeyId='5917'>BXy0hosclJVVrMWI3ydg1kmSWwlAf6gb6g6cGTli7WYe</preKeyPublic>
        <preKeyPublic preKeyId='5918'>BRRf8qxyv7soCjma4aegZZXDZQqXTLvB6XyAYzt7Wnoz</preKeyPublic>
        <preKeyPublic preKeyId='5829'>BWNznSYdJAs4n8XBD4CBp0k1jD16jK6KQYoONGpYZ1kz</preKeyPublic>
        <preKeyPublic preKeyId='5863'>BQFokaGlkNxeAAolaxDnS4vw3RxDGiNRVrpbflHXWoUC</preKeyPublic>
        <preKeyPublic preKeyId='5849'>BRDVe3fDvq9eLSeWRgtYx2FE8+Pro9PFnNXI85wk1tEo</preKeyPublic>
        <preKeyPublic preKeyId='5839'>BRn4UxU0XvjCwDPw3Zrx3k9d+4VKSkWgTKvkWUnzCdMR</preKeyPublic>
        <preKeyPublic preKeyId='5821'>Beg7bbtZ0xk0JKV4ffYAJvl+vH70vmLG+y2y8znNwV5l</preKeyPublic>
        <preKeyPublic preKeyId='5884'>BdW+7texu+KwozY5zTH0iWIaIfCNz/PlFHG5NwagOVlO</preKeyPublic>
        <preKeyPublic preKeyId='5825'>BZYUH68tYOBX7/6huzadBBU/VvnAm2YIJYtfgEpHBRJT</preKeyPublic>
        <preKeyPublic preKeyId='5866'>BSk6Y+SSBixdVPBOsOZ8R3jJsi/XViCe5XZYY8NBWvtv</preKeyPublic>
        <preKeyPublic preKeyId='5867'>BWe0gdkV1Za6kKrP1wQAeO/uM4iERhQYUFAQ3p6fuzci</preKeyPublic>
        <preKeyPublic preKeyId='5869'>BV1i3ht5V5x9al8waIEJnFbt2/Xift5iNYZytIbbqK1N</preKeyPublic>
        <preKeyPublic preKeyId='5854'>Bdn0QHvN8Froa181NT6tjBhn3lolcvfmQ0PgbOFFwyUr</preKeyPublic>
        <preKeyPublic preKeyId='5904'>BXR4svks1GBswheJH8nA+EHMrhAWDhpFGVhV+UpA+nYT</preKeyPublic>
        <preKeyPublic preKeyId='5890'>BS1cZkczpar5JRzp23RiQ55MFnyKTv/MCeoYpq4Bl546</preKeyPublic>
        <preKeyPublic preKeyId='5909'>BaVVtj4gPWu8/xwQix8iOvmoCXA86HE49CEJMedIvWEt</preKeyPublic>
        <preKeyPublic preKeyId='5903'>BbWDDiIAzLWOUypFfJ1e9b45aCettaWXqSWaBy7lTmcM</preKeyPublic>
        <preKeyPublic preKeyId='5897'>BdvpTMGKLEEKkAQiDRLhLi1WR2+oXfqfWb1KFM6fmEQM</preKeyPublic>
        <preKeyPublic preKeyId='5908'>BU62eTQvVp+7dWDp3DAB2eNi5dzA/m2x1ANjEOCz7ug7</preKeyPublic>
        <preKeyPublic preKeyId='5857'>BXyki6cnAr3uAdOFGVvZ56bhJhhtmKnpeSR+NqKJRLIn</preKeyPublic>
        <preKeyPublic preKeyId='5840'>BZEJwaiO505qyWka7YcH0K/3b3zyGyL4tUApABgIkgoU</preKeyPublic>
        <preKeyPublic preKeyId='5912'>BYicqHD/Ub4UeIcvep08bXJtPb8VmelkIQehY0JmL6sS</preKeyPublic>
        <preKeyPublic preKeyId='5851'>BS84+/tTTUdEQ4m/R/kdr/GZ3GBum8e1kd3BCr0efMUA</preKeyPublic>
        <preKeyPublic preKeyId='5875'>BcWA9eGljsPFoQ/KLt/vOeK9Rh9gco3iMPy0++B9S1ha</preKeyPublic>
        <preKeyPublic preKeyId='5824'>BTGXCbWQ+KepPc1He9UB+nQ2uDrbCkoIq9zBsQps4RU8</preKeyPublic>
        <preKeyPublic preKeyId='5820'>BXLYIzHqVkJ+96o+BeI/cZbnbHDLw1nzqi+exfTdMa5O</preKeyPublic>
        <preKeyPublic preKeyId='5845'>BaOYIeSOlRTspiAdO8bi4A7UOnvIamIu3vcHmfQE6ZIy</preKeyPublic>
        <preKeyPublic preKeyId='5893'>BRT21vlH1P+LpSkh9CwqUyMV7ZKgifEj5du2D79wLKtf</preKeyPublic>
        <preKeyPublic preKeyId='5874'>BYv7Zpz39H5clsQwPNaHo35HuIys//FTjVGI9dz7QydK</preKeyPublic>
        <preKeyPublic preKeyId='5853'>BViN7ECDYk1D9kN9LbfYNUPRZA0yYEInd7pTi0eEIr4C</preKeyPublic>
        <preKeyPublic preKeyId='5859'>BZfReXWTb1E23XJQfGh5/MuT1NpZ8Ld8eeXe4ac0s8NX</preKeyPublic>
        <preKeyPublic preKeyId='5881'>BcZPgjqbMYbOpb6Gd5k0zSQHcvspO6+HxU3W2DAikd5m</preKeyPublic>
        <preKeyPublic preKeyId='5861'>BXl/vzxVU0xVeU213H7euVPaS9e/9qOf61mzQs0FlTkw</preKeyPublic>
        <preKeyPublic preKeyId='5878'>BQ+bfZKgexputbmzuT1UqzHUBnTyUeThJTPS26+3d/Bm</preKeyPublic>
        <preKeyPublic preKeyId='5832'>BXyc4yKor8gC8+9377Ewv1WGsuzZaf0k4kFmNz4+KJ0u</preKeyPublic>
        <preKeyPublic preKeyId='5841'>BQ1zh41pYbAd9GX0fUJayIbKkF0vRm4FJxD4fPFRuKFn</preKeyPublic>
        <preKeyPublic preKeyId='5901'>BRWnP06DqgdavHyT5MjADVKXphIl+DeyaSzBU6Y06qAH</preKeyPublic>
        <preKeyPublic preKeyId='5885'>Ba1eeVKgbBPvUYFjqMhqkPAJNPLDwUN8ieKu0iDBU39k</preKeyPublic>
        <preKeyPublic preKeyId='5900'>BVpf4YT+30i2Q70LyPExFQP9J9ajS7VKCsppL1TgJKBV</preKeyPublic>
        <preKeyPublic preKeyId='5852'>BWbYZNxNcaLr2FYASUnZFLK9AxIX0iUMAARV3ll318RP</preKeyPublic>
        <preKeyPublic preKeyId='5834'>BZ0iuMmeLvNZ3gfwe8ZguCnM/7lLuqmtSK7GSs6GyLhM</preKeyPublic>
        <preKeyPublic preKeyId='5855'>BT5r/RnwJYIZYXr4kjZ5l6pIBq/mwyHjWvueQ89fZxRr</preKeyPublic>
        <preKeyPublic preKeyId='5913'>BZFYhlULNbnJjUA66Kayvocee5hvpm6SKeThf0tw6cok</preKeyPublic>
        <preKeyPublic preKeyId='5819'>BcXdkyGzzWqNnz1GqCgWH+xCpOkUwf2q/BPqGG2RgT0t</preKeyPublic>
        <preKeyPublic preKeyId='5899'>BXsvZ0V4w3rQo56sNA3NxtJgUAqBNc1qUauYlJkJMvB4</preKeyPublic>
        <preKeyPublic preKeyId='5850'>BY9em6Byl00j80Vj+swc46wQsq64tqqbZmiL0a4HHt1d</preKeyPublic>
        <preKeyPublic preKeyId='5848'>BXRT5B3XexxnawKcw8yatUOy7cnp257ipNjikOO7aqks</preKeyPublic>
        <preKeyPublic preKeyId='5858'>BSXxCHbH7k2EvwMd2w3spw8askuAQ5tAl+7EP3bZ8O45</preKeyPublic>
        <preKeyPublic preKeyId='5896'>BQ3yASJThR/+43oAv7mTnwa6ne/+CtkgA6gVLDw4Sq1j</preKeyPublic>
        <preKeyPublic preKeyId='5818'>Bb9ST2kJQ1UYxKrhbJ5kkXqwJndrpfIjfZ4Xa3PZ1dxR</preKeyPublic>
        <preKeyPublic preKeyId='5910'>BUsYERpqsC4OxKTpzNPaSZFuc1G8nwfdX6ApcLBa/tw5</preKeyPublic>
        <preKeyPublic preKeyId='5823'>BUT5homnoJA05CBlORBGZKd6TjcHVnykZJmsSThlDJIA</preKeyPublic>
        <preKeyPublic preKeyId='5833'>BeeF7XIa9Dqrvwc4ND+x3EuHc4hVA7ezFAziRhWlj9oA</preKeyPublic>
        <preKeyPublic preKeyId='5906'>BfVvvjKBN5r/GE8q0bJOttEf+Z5ykEx+D2shi7E4BpY/</preKeyPublic>
        <preKeyPublic preKeyId='5842'>BUsYxKz4Mh7u2jeslu39s8k6oQKNuy24cWhBiUYEgxZT</preKeyPublic>
        <preKeyPublic preKeyId='5826'>BR3q9K197h72ghdSptJ8JEFOrGXXkw56S2qTeqdaEVQi</preKeyPublic>
    </prekeys>
</bundle>
"""

    if bundle_xml is None:
        raise omemo.BundleDownloadFailed()

    return oldmemo.etree.parse_bundle(ET.fromstring(bundle_xml), bare_jid, device_id)


class LegacyStorageImpl(LegacyStorage):
    """
    Legacy storage implementation that returns fixed values.
    """

    def __init__(self) -> None:
        super().__init__()

        self.__own_data: Optional[OwnData] = {
            "own_bare_jid": ALICE_BARE_JID,
            "own_device_id": 276148623
        }

        self.__state: Optional[State] = cast(State, {
            "super": {
                "super": {
                    "changed": False,
                    "ik": {
                        "super": None,
                        "priv": "+M1HrVjmqCNgz8sQkZ5KW+iO2B7spff02gPsb4DnSkw=",
                        "pub": "oHyHRMLvUnurWdm1V1l/emyJgkcR0zJWHAewttlZFGI="
                    },
                    "spk": {
                        "key": {
                            "super": None,
                            "priv": "+JWApHPt5O/2JRgoxvA5nzTqxoKpfXSN2L8IpFGX4WE=",
                            "pub": "EAYQBOb83zkY/GkUuIKClpakmtIUcOu4oPHjfjAXbWs="
                        },
                        "signature":
                            "5uTepMjiZq5CIoupPnxj97kB3foXRAE7aGknuxk55kFp2F6HbQbMd6hEDwupsnEAi9AggdCuBFZI6qli"
                            "3kG5DQ==",
                        "timestamp": 1667593793.1751611
                    },
                    "otpks": [
                        {
                            "super": None,
                            "priv": "kFQZv2Kbs2/7I9Zlj9iVzeDh1XML/+RsezHzevGLbVI=",
                            "pub": "41S7dSNRKVydHJ9SQf4BdTzOFapJMOoZDtwTwjwRt0U="
                        },
                        {
                            "super": None,
                            "priv": "GAPUHkvlAPGnmnT/7ltmZ8cCWoW3A+9088yZ/LfomGE=",
                            "pub": "ClQ7qq9NRf4FSLBMQuV9q325lE2uEMIZT34wsvMKMw8="
                        },
                        {
                            "super": None,
                            "priv": "GPVfnu22zx5t131GVM+La0vceiwyDSmopoPuRIvMtn4=",
                            "pub": "8yRIFtKVMh1PBw0x1/atlHThF7mFpiJgLHesUp9pIUU="
                        },
                        {
                            "super": None,
                            "priv": "CNvxvyQB5m14/5ofwn/kaVmi8yR6m4Pyz2DscYtqyWo=",
                            "pub": "tJQ4Kw1usVCj1VeV14KwvJWGi9aCIAMtHnM5lYoZ0H8="
                        },
                        {
                            "super": None,
                            "priv": "IJHXrt/BnLZ8DY8+SL+NysTZ+ebb5f9YgO7jiIyqiGA=",
                            "pub": "b7HbOl4v5f3SWISaR1QxTMWXPhpMhKqeabfSz1Zh6Tg="
                        },
                        {
                            "super": None,
                            "priv": "6HeDxD++ErfAIpY0j+Dgbs9Mbr7nvuflBXFeS0+W4k4=",
                            "pub": "FjO3PTDlDHAWJ7WWmMwyNeZpGq+yoyYepOfRGv4DKDs="
                        },
                        {
                            "super": None,
                            "priv": "0CMb0BNDdsJ8ZAljg1IsqMinooIdsiEc6Zy4b+QrP3c=",
                            "pub": "PT+ur+udEwZxxTza9odi4/6MxsvsbVORfPPW5L6R+Ac="
                        },
                        {
                            "super": None,
                            "priv": "iOKrTC0SEX1KMybMbBmmHDrla3wRiX++4vlgPST1CFE=",
                            "pub": "6DnVpyrSMmXBzy5x/CRF3xN3FM2FgdxSOdgpWv4j9hc="
                        },
                        {
                            "super": None,
                            "priv": "8MEb+nFNGs24xzLNjxlokorgxI+ZX8oWjKJsV9INJEw=",
                            "pub": "RmLYhGqfnKDWwV35whaIsV7ppCT6OU00vVla0EcGdxI="
                        },
                        {
                            "super": None,
                            "priv": "yDJaieNZ4oxrJGhgz0fGuEcd9Ohobr29Rga3bmBnHlw=",
                            "pub": "FPHMBS4S6fVpwoVcak5pZc65uuwohCNz6GwieROQGkg="
                        },
                        {
                            "super": None,
                            "priv": "wGbK1HwWG4pfM1eAp8vUqMSHdrI+qsV9zpM4VDoxikU=",
                            "pub": "HKWmWPxezfgwxzO3VLTST3ru7YoB6fmMNyZvaHi5Hh0="
                        },
                        {
                            "super": None,
                            "priv": "MNnozO6X9sLVIcaXU8DPIxmbSfbCJF3CRccs0ItWFns=",
                            "pub": "lPdZUzleiqUnpx26fRtKPGHUEsdwz9mhRnyiixuR7mg="
                        },
                        {
                            "super": None,
                            "priv": "WPlfEQVN6Xl6+IZs1kqlhYdgSfst2YMVd0CXQpQQp1s=",
                            "pub": "qrGI3tmHrREsXUDyqobTdwvyjMZtBg3kQ7crPP88VWQ="
                        },
                        {
                            "super": None,
                            "priv": "gE2mfvaCt6NekbgC91DkPYvEzESIvkkN2tqxru6zI2M=",
                            "pub": "K1HLNLtA0+qW548MV+7pG1YusnZgWn1TJreIAUFMkW0="
                        },
                        {
                            "super": None,
                            "priv": "8Fwqzp2wD6H7LwkqECKdcHwgwfOdpjuY43saYgN6+28=",
                            "pub": "m1GFBXk222ZLlg+DF0yQR7pwjOY5uFPpXkha9ncbRFE="
                        },
                        {
                            "super": None,
                            "priv": "eHg30PczXTCQTtLPAbRQ5hxeEl6r90v5hHlCVejLiFs=",
                            "pub": "IIxeWdDj447y95T6Mfe3yWf+81SIqL/qoqc91NXVoTY="
                        },
                        {
                            "super": None,
                            "priv": "UF4lIO7d5N7NBOdrCCBhvybCphr614o6u9YF9kPPX3I=",
                            "pub": "HvuEXlkMSP/LtoHEtSc9vtfVvTn1rpvBVSafGMKWVEE="
                        },
                        {
                            "super": None,
                            "priv": "MNWaALdRBk9GS0unqzsUsJOMsV696MABUaIGLYS/UnQ=",
                            "pub": "9nE2IegsNd6Pn/LPmDeOiD+0oRm5p9jtgOZELpqoQFc="
                        },
                        {
                            "super": None,
                            "priv": "EJzcmI8gaiGtTBRO+jKqrHMQsC6X7cJhNvj5OVfYV0s=",
                            "pub": "UhTG+RcMNL2sk9h8K4IrmtwueWDCXInWaUccXGdF3mI="
                        },
                        {
                            "super": None,
                            "priv": "cG4VBDkONuTL0HtS+ZBBwAOJleM22te1ObXc0lu8+0I=",
                            "pub": "v9yqIQ2CQzepMww91hp7gwqp2jkwk+fUIyRxL0FYkig="
                        },
                        {
                            "super": None,
                            "priv": "GCwejFbW5IPpc+bTAqKOJog3/rg798FbiZK1uVXxw1Y=",
                            "pub": "hH4X5aTc5SmDePVXDdbWZb4+LthUWunQBlAenEMvvBI="
                        },
                        {
                            "super": None,
                            "priv": "yLUi0X+b5pLExUodnt/Om5NhSxhGVsap2Ro55zG2wW8=",
                            "pub": "gwGCg9x0kNyhKlyktkgIunsZJTHFB87151iQUuv1HkI="
                        },
                        {
                            "super": None,
                            "priv": "4AaRHXePXLup+bQmyEifwgD+nzZfa7cHfxrlTdDhGkI=",
                            "pub": "s3ZQNIszY5X3dUOLxc1FMrypC2zYr7NhW+jQxqAc6RU="
                        },
                        {
                            "super": None,
                            "priv": "WA//UNPUomjc8RSQzYWRebjoqPeQJw7c9YNd9qePHGY=",
                            "pub": "aX8ZFXrXNpAYVrxM9niUZrr0pgd4Cby/htPYm3AgRSQ="
                        },
                        {
                            "super": None,
                            "priv": "6PzxgGGCMmejw8tZ8927pxMiujNJOh1jNi5r/mvRU3M=",
                            "pub": "xSyuLDhwepG1Q02OMdHhmbEsIhsRQslasdWlxghlO0Q="
                        },
                        {
                            "super": None,
                            "priv": "6EFDomBwtWkgRgCQh5m4sng8Mc4PYJFO4fODSH/omng=",
                            "pub": "HerZaNtfdnqWjUEXeLL2bKr9BgROO5/77YK3LxXygFU="
                        },
                        {
                            "super": None,
                            "priv": "ODPnjQiY8SqK8aLfRCrGCRzqkakyWbtZBIUKNsMgE0Y=",
                            "pub": "Ju95ww91tBVP6sLdCvajsQpsKbY5RxpYK7qGBXntlxA="
                        },
                        {
                            "super": None,
                            "priv": "uMwiW6Xl9lydY+h7zWQ5nLRGBj9UbF2gX78J2GGs6nU=",
                            "pub": "U2m7JuxUlSy5U6drjomEDJNgdcZyjZLXR3xAIM3zNEo="
                        },
                        {
                            "super": None,
                            "priv": "YA0lrsorffwQ6WECZ49yA+o6fSaOsUQT7GvuOgkFZWM=",
                            "pub": "rh+CFP9CueyyrsjatlyQzxEMSJJLC38wnZ9v4GTiRQM="
                        },
                        {
                            "super": None,
                            "priv": "2NoiZwDa+zOuphWuTe+rj3Pm4jZh9iwjuIfRcr4d3nA=",
                            "pub": "Aq/zIEVWrfedO6PNIp0YsvZuee4430nCP+/aDNoLzl8="
                        },
                        {
                            "super": None,
                            "priv": "oEwKKPemvGjZiotUez0F9V4qS7UdKPApQS4ZFqRRBXg=",
                            "pub": "dR06WpYaFQPJpMn3tUGTxjj93zKRnNfrik7InpJ7I2M="
                        },
                        {
                            "super": None,
                            "priv": "iC1VDpakAzpuhqWeA3N7Lv2aNamNOFZabSd0kyJreGQ=",
                            "pub": "zJTCGQ1u07QzqNI/lO1h3Fm2VSeUN5+jpOezQS9UzSM="
                        },
                        {
                            "super": None,
                            "priv": "AIJ4PHQRNj2WCLYoDUeq4SYBuzKLvvDk1gKuzxRHCFI=",
                            "pub": "DHxfpBwU2ZfzjpKBrFs8g41tEKe0cuVg5iX/cdz4B2E="
                        },
                        {
                            "super": None,
                            "priv": "CE8d0rTpWCtBucQCFN+jGkjaxVziEFQvg6kfu7CiYm8=",
                            "pub": "+NbRFoJi1U1Q7rOi+thCFx19F9ck5IFbIxr0LA/Fsl4="
                        },
                        {
                            "super": None,
                            "priv": "UA+JXlv1FErOH4unObL7xViLjaUJD0Ej2O/ALH6sEUU=",
                            "pub": "B2kVKEPJsE/eRQ4L8VZI5Y8hF2De84TdjIDbN5Rgy0E="
                        },
                        {
                            "super": None,
                            "priv": "OEqhXw4A7GtQZ8Q7uTZRYDBPyKxJAsfsqndo/T3RlXw=",
                            "pub": "fPVUw0LehvfROpbpWSrOVcek6FFWXmffBuhSsTTwaVc="
                        },
                        {
                            "super": None,
                            "priv": "YIqoOvpTczoP2T8RE+nx0HZUmv+A03Brj+YUyl/wBm4=",
                            "pub": "MJdt0wrLpVEbdlm0wrkxZFCwAWUeA2C8DeS7okEDynE="
                        },
                        {
                            "super": None,
                            "priv": "MErJvpd/xnkGdCQfXjiUBW/9M8EEy8AeUCRu9s6vjlI=",
                            "pub": "xM0iZzZdh1YzLqyHDNdZw0kkhdTxpOzso6QKzASGIF0="
                        },
                        {
                            "super": None,
                            "priv": "uHZRlyOPqA9nbxY+xgXRCptPytFnEyih8l72o83+UnY=",
                            "pub": "kzNsqmF0k8n7cVFRR1Gdu9ryPL5kqCM6XUd+ZrqhJB0="
                        },
                        {
                            "super": None,
                            "priv": "IIcCGq4o9zfGRFz1bxV3IvU7bUQ/4xcKi4NKOnySEkE=",
                            "pub": "gETvwxDOJ6hOzrhhlZDx/Oo/eJPy7d+pmC2qTYtyI0U="
                        },
                        {
                            "super": None,
                            "priv": "4HXhyEclIEoXA0320fj75+1tAfFMeXIv45PjasPhQH8=",
                            "pub": "rsq44EVHtA924hTqNAdOyJEEBDdxVjw69yKRSeIZAxg="
                        },
                        {
                            "super": None,
                            "priv": "GE3zmrDW/hrri7xTKVaQSMzhd41Ngrm/pe2/gl7bemA=",
                            "pub": "oaU/GUM/8oLfXzXxYf2sLzpnddsP7+3e4KcZ7lNfNCs="
                        },
                        {
                            "super": None,
                            "priv": "gDzKDG+B1WQWHcJn2xlV2WvoDO900qcnvH2ZYBnbj1Q=",
                            "pub": "YmXis/URH38SgxDZhVdLJzBqzQl2sorp3F5T/Mlhsyg="
                        },
                        {
                            "super": None,
                            "priv": "OKyNFXO5OyaOpZeGqDvFDwReYoxkgVpYTSuvu0FFsH8=",
                            "pub": "yWWkqcTs98xMkSOTPvNhGlDH73H7XECcOWP/aXgYzjs="
                        },
                        {
                            "super": None,
                            "priv": "oDysGXfqJNLDHLaIsVn5OewymKalLpgh0BKbvcvaIWU=",
                            "pub": "1g8yopekUKG9ENEAHj/GF1A2iM0Fni8hxP8btTx3r0Q="
                        },
                        {
                            "super": None,
                            "priv": "aMYEhAsVWKtiA8zMpz3bpOw7xVqzpMnbp4TWZVoytUE=",
                            "pub": "atnc1M+e3c1RY3RJ15sju8KzSzYoVk7NGRCxlg7KWlY="
                        },
                        {
                            "super": None,
                            "priv": "ONFc9ZqPHIWJLKyg8aqDbcRU7MMhMVoy60ug1EnHMnk=",
                            "pub": "X9cA0kv2fL+jYs6xvOyTcCRji9yCvDy8gs7VUJK+OV8="
                        },
                        {
                            "super": None,
                            "priv": "wNiy3KfE2BCRvJk0bNN4ANDYAWSzPh0oJGQHy5m7mWM=",
                            "pub": "ebeKRJLFey4m8lSp8XTEjrBZ51abQYd+Y0SxcRlW8F0="
                        },
                        {
                            "super": None,
                            "priv": "cA9seVGK11bHqESI5CqYCUizX4TMrZRCAtsoVOzXgWg=",
                            "pub": "7Rqnx+j4Ww7iZARcVAWQPV4FjyGfbVfoxjs5imvpyHk="
                        },
                        {
                            "super": None,
                            "priv": "OKQAojMm68A6CK8hnIH+3oHKgF6DvOyVUU9OJNdkX1Q=",
                            "pub": "4vKnajBleMp8eOQZ1QMkGdeXMuewYaXJtx+NkraGDB8="
                        },
                        {
                            "super": None,
                            "priv": "UJdLlpbXHVnjNHZpPFiYI4XObwUs+GjE6UBh42NQF34=",
                            "pub": "nbejftco5w1tYU71ECAoClS2Mmcny7L/55c3l7v1AzM="
                        },
                        {
                            "super": None,
                            "priv": "AMqEW0eZqRXhRGg0E8NamDni6/0SyEppemJ0Ltmtz3o=",
                            "pub": "KfEkWY1QiIAPMxJZyYbLO4I85/kMH71M0qKR0NQwWn4="
                        },
                        {
                            "super": None,
                            "priv": "qClB/d1Nj+5hMsL7Fz/QAP1tC6LjwQPLkyKwNkvZrXA=",
                            "pub": "9sESsr8aGV7JFvFpYEIsMowr3ZPPxAoUoHfm6Q/Wijg="
                        },
                        {
                            "super": None,
                            "priv": "kKqq3XGrJHeXX01vmB4GhCVkcVezZitIkANbnIXE320=",
                            "pub": "9Mo9uEXUwilJ0e3MM8N3JEB8WHoWrQNSj6LwHbJyfW4="
                        },
                        {
                            "super": None,
                            "priv": "SMg0RaXDWXKc1Av7zxQRDIdFQQ0AHQIP1wFUUHbUW2g=",
                            "pub": "nFogNYeA/jKv7KVcHrNa2X5DdA4Uc/I5aANSkf9zmzI="
                        },
                        {
                            "super": None,
                            "priv": "4OgEQ92QcS6yJjXqjhdvZ2lt9nF3qNLtYqhDt7ZZm0o=",
                            "pub": "XS+zxEPCLT9PDNo5um1OHUxSHGI81PmYayX3BjJBmBQ="
                        },
                        {
                            "super": None,
                            "priv": "CF1pK767lsf7OkAtz3Qop2PlCEV2C77Uf9q7XH6uIEM=",
                            "pub": "z+VNvM9LK4czcAbu/IlOuauVqpyDg8Jg7r8mVEJnsH8="
                        },
                        {
                            "super": None,
                            "priv": "mHDIJM+NgU/Fq3PQw7HwHg57RapQRaTJ4HW10UWIBHU=",
                            "pub": "TSwE9ecYq7+ZH4Ap9wf3dbgkBYGxhD4Pw5KsOqlj11w="
                        },
                        {
                            "super": None,
                            "priv": "ICUKlcCbxiYObQ6uN4tLy7T06Yrfk1dtC1wZmlD9mVw=",
                            "pub": "2RR/5si4BorIjN90Ge/ou+6xynroIVHgw7sMvQMxYg0="
                        },
                        {
                            "super": None,
                            "priv": "4CVspGaK5tRhrinwebNGqwXnvfaPiB1HVsVRX54cqHY=",
                            "pub": "yLW+eDVjKuLFGkpzz6TQMLj5GRlKmsCe5/ZyyzNm82c="
                        },
                        {
                            "super": None,
                            "priv": "IExm4y9ySzjCKYUp5pcVr0mUh5fJfEmMjoKzM2qETU4=",
                            "pub": "6nKEvzz2teIgm0O5dmq45htRZnsHfQxYWOb1TM8nxgI="
                        },
                        {
                            "super": None,
                            "priv": "sPusbvGpf/ncR46djUulpOS6hv8ZdmWZV5ecPwdMJGw=",
                            "pub": "UPuNJXIgFtRq2cNdennh2A/S6iWGntNqlnJGqld8CgI="
                        },
                        {
                            "super": None,
                            "priv": "UI95zjR5wMUIFjTQv/k27Oljlxpn+blKrNZ2Sgwic3w=",
                            "pub": "8j5e8u1N5AY867W4n5oStX5aj5oLKfmE/RCQ6GutQFA="
                        },
                        {
                            "super": None,
                            "priv": "aOcy3j3MYalwEzhZW0soFLSZrcJIpimSPYeVdhiy8ks=",
                            "pub": "5yh6HIBy5ug/BEN/D3grkrjjgXn13irO3pbLH3e94mA="
                        },
                        {
                            "super": None,
                            "priv": "GMvCW4ho56dHPZIvxXuiEKUyxCwKikqYx+w6+DbKVGU=",
                            "pub": "2aIIr6aSkHgfKC91CZaHLMPfrGjQvX/YIjhWCMiCYhI="
                        },
                        {
                            "super": None,
                            "priv": "iMfkuI9jAOmjHJYihzo9sU/pCsl7iOWacpHAvzRrLmk=",
                            "pub": "A7QLJYguJlY66QIfqKN1P7cnxDPMWaeEbpw638dB2Uo="
                        },
                        {
                            "super": None,
                            "priv": "OKa3qVdxHh4QvCAUdru1Ovag3I9XUGhoMGS/IbECoHo=",
                            "pub": "FUhXrs+76feCJZpMnKIx4WGxpxaCRecPYfDSkrZC3Gk="
                        },
                        {
                            "super": None,
                            "priv": "SBuBZShOtNadkLLpbKaD3l/SXad6CFmamul2NA+t8l0=",
                            "pub": "cV0GOKR5Gj/rO6XC2/qWS0QLYtsNDy4j7cFsHOj7ums="
                        },
                        {
                            "super": None,
                            "priv": "sK6Ubr0YsV1bYSP+DzIMkKbdFeJI5MgIWjXYpkY08mY=",
                            "pub": "hBUjJFWTcWByp5Eg31wdWnMPnuyWD5/5OWd8KvOxFic="
                        },
                        {
                            "super": None,
                            "priv": "4DdaxOC8YnUXJ4F3/7T/5l1yCdIX7x6A16vah/ZiGVc=",
                            "pub": "OnFmWqmIcCKdb0LxkZfdKeT+Hjyps+KdAFdM5QkylzY="
                        },
                        {
                            "super": None,
                            "priv": "eIT08Y+i5Zf7LgQaAEGQz1cmu9lFbC4Nz8NTsW8MI0Q=",
                            "pub": "YawTJwMZe94slER0Cv9E62BT3dBdmmA5yqIRfIlRGTw="
                        },
                        {
                            "super": None,
                            "priv": "iAmI7HAr4zjGNQOnKOntYM8mIEwxIML5sWAQ+7Uk5nk=",
                            "pub": "I0Jousik3YPgs+LsOrPhNND/ZX7SYSZxvjf6uDmOBwg="
                        },
                        {
                            "super": None,
                            "priv": "YOSgu0p7xaxK1OsPJ1ZsWVYojCFAGo5D3ZeXWPZqG0I=",
                            "pub": "RIROknKScmUZbdWd542QKXnU8YQ+HZzyUEe1r0DtFGg="
                        },
                        {
                            "super": None,
                            "priv": "qJWQDMjdqvU/x6LRxOs0Bf9Qdf5ydK0HO3T6yjYLhkg=",
                            "pub": "+NRU6JZMG6FeE16vMPl8r6GW1QPFNw5h0M6eKN+pMjs="
                        },
                        {
                            "super": None,
                            "priv": "6LJvq/l+UHtJDC/o6vkvRRz6vuAiE/Ah19viiMBRZ0E=",
                            "pub": "WTcy7ztqBGWk5Ou3/keANSPzIettx+XMduCVGdh5QDw="
                        },
                        {
                            "super": None,
                            "priv": "UJBckDbyGxs3mmWMwmQVeS62fSm1RaAE0Shu4LKF1Xs=",
                            "pub": "mnB2Ix8fzU94/x68jIe+DkinqoBu/oE7ApFkkA+zsQQ="
                        },
                        {
                            "super": None,
                            "priv": "kDnWXgp2xuNtB+O1s4m4LDaQqSmoTwkXgASA8ZzRCkg=",
                            "pub": "wAxu63Gqkv/zyihOWOkbJ2buJYue6ymAecLtEstgEDQ="
                        },
                        {
                            "super": None,
                            "priv": "iKvrVvjvu/sUXbM/h4TmtxQMN78YvRmE6BkD84cI80U=",
                            "pub": "ABPvaQzCV+4PN8cQcPOsmszPBmh5AFNMGowqCCb19xQ="
                        },
                        {
                            "super": None,
                            "priv": "UPUZgmMv+ISJg3bDXJPqQJ1J53sdm7vDldyg0y3B11M=",
                            "pub": "cs72j7+A4eCNB5AkkQ1VO+u+Xs4ZZBX1/7ipa2NAhhc="
                        },
                        {
                            "super": None,
                            "priv": "CBhDQ5nVkLLyGDDk2CoxBuw9CIGzyrpMAK9OiGN03Ew=",
                            "pub": "bkDHA5XwcBKLIbttXKc1+7xyjR52VtheTm+wDvnq2FM="
                        },
                        {
                            "super": None,
                            "priv": "OJl7ffY5rI/ZX/4eZ5VdOYG6/EIqtgCzYe0L/Z0gR0E=",
                            "pub": "cJs6nlt05LXQNwRgm2cvzRVRO0trhq67gxPV3fNyBwU="
                        },
                        {
                            "super": None,
                            "priv": "2Mg/MlPyPJj7NMJviG0EojVLMYdqV3FombtvjbOL130=",
                            "pub": "2pi7faDWnrbgJ2W9KSNe2QTh+mcYYZ4XD72I3S/CJTw="
                        },
                        {
                            "super": None,
                            "priv": "WJ/jaLvffvNLayDY2kyhjnfqe4w2lFXnbivQEe4eK1s=",
                            "pub": "D9nnf17Mdk83wMn3n6vDZK7quxR9f/bdZGfZpePlr0I="
                        },
                        {
                            "super": None,
                            "priv": "6GLCmG5i0jSPFhbraPydla8BpZLLuTSbt64FCN/bw3M=",
                            "pub": "1lkK9gu3xUx3PSmAWfO0+SDxz7ZT6rs7qcbqPnN8RhQ="
                        },
                        {
                            "super": None,
                            "priv": "+OuOxUB5HlKs/408iQu3Hjlc99w7S4zAr8PrD2670E4=",
                            "pub": "YJjkYGH6wqkaJG9j4IP9pISfhmJHkIGBD/KNcvAuITU="
                        },
                        {
                            "super": None,
                            "priv": "KBcUflAZT2F3cSOZ6+KXLyujTBnP00tpICYOHx4zZGU=",
                            "pub": "Rz7ghRra3Pva/1Dw8gghpA8Dk4cZ11aDi3JlpLOVvgA="
                        },
                        {
                            "super": None,
                            "priv": "kMtjlWUNTDYj7lX6+bxit61fVT71kh6NwfetbxRjnHM=",
                            "pub": "r7/ajemf9F4UNm/8LCXIDIibhfMbLd1s2JYLV8fhEBw="
                        },
                        {
                            "super": None,
                            "priv": "QDYU2Mq0mAX1baYcrHn248sdPnJJlFDDJ2n+JIvwBEE=",
                            "pub": "x3nIy+WKK+6MZQfyat9Atyfqy5ogLT8bdWmAJW5gjFI="
                        },
                        {
                            "super": None,
                            "priv": "2JD+UqSsDlPbpnyLdySaQoSQcc3jzEq41UBpfh0M/W0=",
                            "pub": "J6dSqOZfoLyoSdRuFMNxkGxWfbAgz213t3XI6cMrAyM="
                        },
                        {
                            "super": None,
                            "priv": "4GvE/E+Yw6WIIkViiWjWggJ18lmvJQfogtck8jT9IXQ=",
                            "pub": "WF/8K64orfX5p/K599Nals4TbIWzXwUmDuckQrr+Dgw="
                        },
                        {
                            "super": None,
                            "priv": "wKycN3aHrlwNUSpUSa8D9jEoumvvDsj0daCKc4BFUWM=",
                            "pub": "Y/oF8RU8pSfDjbLYyiQ0uoOLhysDUoyKD6mElqS3SUY="
                        },
                        {
                            "super": None,
                            "priv": "OJgPXDyrVgCjQaHVGvN2zSYebWRol2HXC6ZbWHsHMnk=",
                            "pub": "EtxHTpmG7qFVib00v10yiiKgBxeT9+iM1GYsHnkhgno="
                        },
                        {
                            "super": None,
                            "priv": "qHKQKWDRYYEWuaMU1fRa5W2IbGAizOJBC4RYKpKJ3XE=",
                            "pub": "mm8grWur9BFBq/LQ+sYAxExPDxAtuCIDQI7KAelleUs="
                        },
                        {
                            "super": None,
                            "priv": "WJdQ/eh5Z1EkrP5Fik9eU2FPAdltVyEAw5rW6Q9cZW8=",
                            "pub": "a4xJM6F6Uce+hT0i6DjHtkYoues+1g5zTHgD7QSd1TY="
                        },
                        {
                            "super": None,
                            "priv": "oGIW69kG33UbOJqktM67l95tDqYsJSyb0fsxR/i24kE=",
                            "pub": "/Kl4Pe5/hShxK6i/FtjGKyoT4ipx8LQr5BMrFgcNoDo="
                        },
                        {
                            "super": None,
                            "priv": "eKK0OJlJMmU7snaJVVXCDc47V1XKtk/WecmssHYj2lI=",
                            "pub": "Ctw1qgY2LnCU/U2EgsOzFZfFWURT41Z2C/19R1wwQys="
                        },
                        {
                            "super": None,
                            "priv": "iGwe5tQpiWRfz/6LTi21ZD0Uz/wTF8G3w/esWy7k/FM=",
                            "pub": "oU1mCSV4AJ2wik+LNhPa7kfJdPb2ha8YEsatz40zvGY="
                        },
                        {
                            "super": None,
                            "priv": "MKc/jAPanYLugJWPRnNLdWCDqDX2dAR429Tnmfi/r2U=",
                            "pub": "BkdzjP8vNkN2NJ1+At1af82Z3CscOJjvqmDj0t0Ydks="
                        },
                        {
                            "super": None,
                            "priv": "kIRjgh0PHtrEJiTFgL9G78ovpDtye3NdLrK43SNMaVc=",
                            "pub": "nZS/+C95Zfqm92zMozo9yk24TSaUh0VzQwpG0g6YIgM="
                        },
                        {
                            "super": None,
                            "priv": "cGnyqU3mnT5xUN1/4gISbzvdeYK5P0U4/qlUiqJ1y0I=",
                            "pub": "czLbCbtZYhw7qDrY9GKLGZQYiO9A30aDJCRa4SgLIn4="
                        }
                    ],
                    "hidden_otpks": []
                },
                "spk_id": 1,
                "spk_pub": "EAYQBOb83zkY/GkUuIKClpakmtIUcOu4oPHjfjAXbWs=",
                "otpk_id_counter": 100,
                "otpk_ids": {
                    "41S7dSNRKVydHJ9SQf4BdTzOFapJMOoZDtwTwjwRt0U=": 1,
                    "ClQ7qq9NRf4FSLBMQuV9q325lE2uEMIZT34wsvMKMw8=": 2,
                    "8yRIFtKVMh1PBw0x1/atlHThF7mFpiJgLHesUp9pIUU=": 3,
                    "tJQ4Kw1usVCj1VeV14KwvJWGi9aCIAMtHnM5lYoZ0H8=": 4,
                    "b7HbOl4v5f3SWISaR1QxTMWXPhpMhKqeabfSz1Zh6Tg=": 5,
                    "FjO3PTDlDHAWJ7WWmMwyNeZpGq+yoyYepOfRGv4DKDs=": 6,
                    "PT+ur+udEwZxxTza9odi4/6MxsvsbVORfPPW5L6R+Ac=": 7,
                    "6DnVpyrSMmXBzy5x/CRF3xN3FM2FgdxSOdgpWv4j9hc=": 8,
                    "RmLYhGqfnKDWwV35whaIsV7ppCT6OU00vVla0EcGdxI=": 9,
                    "FPHMBS4S6fVpwoVcak5pZc65uuwohCNz6GwieROQGkg=": 10,
                    "HKWmWPxezfgwxzO3VLTST3ru7YoB6fmMNyZvaHi5Hh0=": 11,
                    "lPdZUzleiqUnpx26fRtKPGHUEsdwz9mhRnyiixuR7mg=": 12,
                    "qrGI3tmHrREsXUDyqobTdwvyjMZtBg3kQ7crPP88VWQ=": 13,
                    "K1HLNLtA0+qW548MV+7pG1YusnZgWn1TJreIAUFMkW0=": 14,
                    "m1GFBXk222ZLlg+DF0yQR7pwjOY5uFPpXkha9ncbRFE=": 15,
                    "IIxeWdDj447y95T6Mfe3yWf+81SIqL/qoqc91NXVoTY=": 16,
                    "HvuEXlkMSP/LtoHEtSc9vtfVvTn1rpvBVSafGMKWVEE=": 17,
                    "9nE2IegsNd6Pn/LPmDeOiD+0oRm5p9jtgOZELpqoQFc=": 18,
                    "UhTG+RcMNL2sk9h8K4IrmtwueWDCXInWaUccXGdF3mI=": 19,
                    "v9yqIQ2CQzepMww91hp7gwqp2jkwk+fUIyRxL0FYkig=": 20,
                    "hH4X5aTc5SmDePVXDdbWZb4+LthUWunQBlAenEMvvBI=": 21,
                    "gwGCg9x0kNyhKlyktkgIunsZJTHFB87151iQUuv1HkI=": 22,
                    "s3ZQNIszY5X3dUOLxc1FMrypC2zYr7NhW+jQxqAc6RU=": 23,
                    "aX8ZFXrXNpAYVrxM9niUZrr0pgd4Cby/htPYm3AgRSQ=": 24,
                    "xSyuLDhwepG1Q02OMdHhmbEsIhsRQslasdWlxghlO0Q=": 25,
                    "HerZaNtfdnqWjUEXeLL2bKr9BgROO5/77YK3LxXygFU=": 26,
                    "Ju95ww91tBVP6sLdCvajsQpsKbY5RxpYK7qGBXntlxA=": 27,
                    "U2m7JuxUlSy5U6drjomEDJNgdcZyjZLXR3xAIM3zNEo=": 28,
                    "rh+CFP9CueyyrsjatlyQzxEMSJJLC38wnZ9v4GTiRQM=": 29,
                    "Aq/zIEVWrfedO6PNIp0YsvZuee4430nCP+/aDNoLzl8=": 30,
                    "dR06WpYaFQPJpMn3tUGTxjj93zKRnNfrik7InpJ7I2M=": 31,
                    "zJTCGQ1u07QzqNI/lO1h3Fm2VSeUN5+jpOezQS9UzSM=": 32,
                    "DHxfpBwU2ZfzjpKBrFs8g41tEKe0cuVg5iX/cdz4B2E=": 33,
                    "+NbRFoJi1U1Q7rOi+thCFx19F9ck5IFbIxr0LA/Fsl4=": 34,
                    "B2kVKEPJsE/eRQ4L8VZI5Y8hF2De84TdjIDbN5Rgy0E=": 35,
                    "fPVUw0LehvfROpbpWSrOVcek6FFWXmffBuhSsTTwaVc=": 36,
                    "MJdt0wrLpVEbdlm0wrkxZFCwAWUeA2C8DeS7okEDynE=": 37,
                    "xM0iZzZdh1YzLqyHDNdZw0kkhdTxpOzso6QKzASGIF0=": 38,
                    "kzNsqmF0k8n7cVFRR1Gdu9ryPL5kqCM6XUd+ZrqhJB0=": 39,
                    "gETvwxDOJ6hOzrhhlZDx/Oo/eJPy7d+pmC2qTYtyI0U=": 40,
                    "rsq44EVHtA924hTqNAdOyJEEBDdxVjw69yKRSeIZAxg=": 41,
                    "oaU/GUM/8oLfXzXxYf2sLzpnddsP7+3e4KcZ7lNfNCs=": 42,
                    "YmXis/URH38SgxDZhVdLJzBqzQl2sorp3F5T/Mlhsyg=": 43,
                    "yWWkqcTs98xMkSOTPvNhGlDH73H7XECcOWP/aXgYzjs=": 44,
                    "1g8yopekUKG9ENEAHj/GF1A2iM0Fni8hxP8btTx3r0Q=": 45,
                    "atnc1M+e3c1RY3RJ15sju8KzSzYoVk7NGRCxlg7KWlY=": 46,
                    "X9cA0kv2fL+jYs6xvOyTcCRji9yCvDy8gs7VUJK+OV8=": 47,
                    "ebeKRJLFey4m8lSp8XTEjrBZ51abQYd+Y0SxcRlW8F0=": 48,
                    "7Rqnx+j4Ww7iZARcVAWQPV4FjyGfbVfoxjs5imvpyHk=": 49,
                    "4vKnajBleMp8eOQZ1QMkGdeXMuewYaXJtx+NkraGDB8=": 50,
                    "nbejftco5w1tYU71ECAoClS2Mmcny7L/55c3l7v1AzM=": 51,
                    "KfEkWY1QiIAPMxJZyYbLO4I85/kMH71M0qKR0NQwWn4=": 52,
                    "9sESsr8aGV7JFvFpYEIsMowr3ZPPxAoUoHfm6Q/Wijg=": 53,
                    "9Mo9uEXUwilJ0e3MM8N3JEB8WHoWrQNSj6LwHbJyfW4=": 54,
                    "nFogNYeA/jKv7KVcHrNa2X5DdA4Uc/I5aANSkf9zmzI=": 55,
                    "XS+zxEPCLT9PDNo5um1OHUxSHGI81PmYayX3BjJBmBQ=": 56,
                    "z+VNvM9LK4czcAbu/IlOuauVqpyDg8Jg7r8mVEJnsH8=": 57,
                    "TSwE9ecYq7+ZH4Ap9wf3dbgkBYGxhD4Pw5KsOqlj11w=": 58,
                    "2RR/5si4BorIjN90Ge/ou+6xynroIVHgw7sMvQMxYg0=": 59,
                    "yLW+eDVjKuLFGkpzz6TQMLj5GRlKmsCe5/ZyyzNm82c=": 60,
                    "6nKEvzz2teIgm0O5dmq45htRZnsHfQxYWOb1TM8nxgI=": 61,
                    "UPuNJXIgFtRq2cNdennh2A/S6iWGntNqlnJGqld8CgI=": 62,
                    "8j5e8u1N5AY867W4n5oStX5aj5oLKfmE/RCQ6GutQFA=": 63,
                    "5yh6HIBy5ug/BEN/D3grkrjjgXn13irO3pbLH3e94mA=": 64,
                    "2aIIr6aSkHgfKC91CZaHLMPfrGjQvX/YIjhWCMiCYhI=": 65,
                    "A7QLJYguJlY66QIfqKN1P7cnxDPMWaeEbpw638dB2Uo=": 66,
                    "FUhXrs+76feCJZpMnKIx4WGxpxaCRecPYfDSkrZC3Gk=": 67,
                    "cV0GOKR5Gj/rO6XC2/qWS0QLYtsNDy4j7cFsHOj7ums=": 68,
                    "hBUjJFWTcWByp5Eg31wdWnMPnuyWD5/5OWd8KvOxFic=": 69,
                    "OnFmWqmIcCKdb0LxkZfdKeT+Hjyps+KdAFdM5QkylzY=": 70,
                    "YawTJwMZe94slER0Cv9E62BT3dBdmmA5yqIRfIlRGTw=": 71,
                    "I0Jousik3YPgs+LsOrPhNND/ZX7SYSZxvjf6uDmOBwg=": 72,
                    "RIROknKScmUZbdWd542QKXnU8YQ+HZzyUEe1r0DtFGg=": 73,
                    "+NRU6JZMG6FeE16vMPl8r6GW1QPFNw5h0M6eKN+pMjs=": 74,
                    "WTcy7ztqBGWk5Ou3/keANSPzIettx+XMduCVGdh5QDw=": 75,
                    "mnB2Ix8fzU94/x68jIe+DkinqoBu/oE7ApFkkA+zsQQ=": 76,
                    "wAxu63Gqkv/zyihOWOkbJ2buJYue6ymAecLtEstgEDQ=": 77,
                    "ABPvaQzCV+4PN8cQcPOsmszPBmh5AFNMGowqCCb19xQ=": 78,
                    "cs72j7+A4eCNB5AkkQ1VO+u+Xs4ZZBX1/7ipa2NAhhc=": 79,
                    "bkDHA5XwcBKLIbttXKc1+7xyjR52VtheTm+wDvnq2FM=": 80,
                    "cJs6nlt05LXQNwRgm2cvzRVRO0trhq67gxPV3fNyBwU=": 81,
                    "2pi7faDWnrbgJ2W9KSNe2QTh+mcYYZ4XD72I3S/CJTw=": 82,
                    "D9nnf17Mdk83wMn3n6vDZK7quxR9f/bdZGfZpePlr0I=": 83,
                    "1lkK9gu3xUx3PSmAWfO0+SDxz7ZT6rs7qcbqPnN8RhQ=": 84,
                    "YJjkYGH6wqkaJG9j4IP9pISfhmJHkIGBD/KNcvAuITU=": 85,
                    "Rz7ghRra3Pva/1Dw8gghpA8Dk4cZ11aDi3JlpLOVvgA=": 86,
                    "r7/ajemf9F4UNm/8LCXIDIibhfMbLd1s2JYLV8fhEBw=": 87,
                    "x3nIy+WKK+6MZQfyat9Atyfqy5ogLT8bdWmAJW5gjFI=": 88,
                    "J6dSqOZfoLyoSdRuFMNxkGxWfbAgz213t3XI6cMrAyM=": 89,
                    "WF/8K64orfX5p/K599Nals4TbIWzXwUmDuckQrr+Dgw=": 90,
                    "Y/oF8RU8pSfDjbLYyiQ0uoOLhysDUoyKD6mElqS3SUY=": 91,
                    "EtxHTpmG7qFVib00v10yiiKgBxeT9+iM1GYsHnkhgno=": 92,
                    "mm8grWur9BFBq/LQ+sYAxExPDxAtuCIDQI7KAelleUs=": 93,
                    "a4xJM6F6Uce+hT0i6DjHtkYoues+1g5zTHgD7QSd1TY=": 94,
                    "/Kl4Pe5/hShxK6i/FtjGKyoT4ipx8LQr5BMrFgcNoDo=": 95,
                    "Ctw1qgY2LnCU/U2EgsOzFZfFWURT41Z2C/19R1wwQys=": 96,
                    "oU1mCSV4AJ2wik+LNhPa7kfJdPb2ha8YEsatz40zvGY=": 97,
                    "BkdzjP8vNkN2NJ1+At1af82Z3CscOJjvqmDj0t0Ydks=": 98,
                    "nZS/+C95Zfqm92zMozo9yk24TSaUh0VzQwpG0g6YIgM=": 99,
                    "czLbCbtZYhw7qDrY9GKLGZQYiO9A30aDJCRa4SgLIn4=": 100
                }
            },
            "bound_otpks": {},
            "pk_messages": {},
            "version": "0.12.0"
        })

        self.__sessions: Dict[str, Dict[int, Session]] = {
            BOB_BARE_JID: {
                543990483: {
                    "super": {
                        "super": {
                            "super": None,
                            "root_chain": {
                                "length": 1,
                                "key": "qdglSV/R3ClGiEkb604glYv4ZR8KT5JGZ9f4LpVb0f4="
                            },
                            "own_key": {
                                "super": None,
                                "priv": "QCK8gHnh2NWJPm+CUhY7Rl8eS9YnY8Qh/25XZKhHnnI=",
                                "pub": "DE332GI542wqdG/qMs0dnwU9GZGdHql9KeogAnnqCVg="
                            },
                            "other_pub": {
                                "super": None,
                                "priv": None,
                                "pub": "s5YiNlC8TML3n3U01WQzqmyznud++YpAsTqaPxEohyk="
                            }
                        },
                        "skr": {
                            "super": None,
                            "schain": {
                                "length": 1,
                                "key": "mWdtSXtFv+Bmt0SiJjhs+dX302KIJfp14Kfmhi9iXDE="
                            },
                            "rchain": None,
                            "prev_schain_length": None
                        },
                        "ad":
                            "BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRiBV9fZvG3d9VDGN5YesFEza85kVg1fghRgw2V"
                            "ufMB1Dov",
                        "smks": {}
                    },
                    "other_ik": "X19m8bd31UMY3lh6wUTNrzmRWDV+CFGDDZW58wHUOi8="
                },
                1746810996: {
                    "super": {
                        "super": {
                            "super": None,
                            "root_chain": {
                                "length": 1,
                                "key": "R++74Y8wNT+cXFyb4Q9Xf9PnBDUxXi2yynKyyVNurgM="
                            },
                            "own_key": {
                                "super": None,
                                "priv": "cEaaTCUUBjLyGJ8WngxV8Kjy3DCzl/j6nTP8G/NZiGk=",
                                "pub": "pWhLUikIlfdIlVRM6J9y3oj7z7LoV929OS4D1dL+ZnY="
                            },
                            "other_pub": {
                                "super": None,
                                "priv": None,
                                "pub": "IipARZXB273UAIKimuZsKVh6jF73zRswAtEukymlWEw="
                            }
                        },
                        "skr": {
                            "super": None,
                            "schain": {
                                "length": 1,
                                "key": "MAy5SWE3pJfaq63IttPWLsaXrfKR1a8NhFfbxKvDP4M="
                            },
                            "rchain": None,
                            "prev_schain_length": None
                        },
                        "ad":
                            "BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRiBepHj/wMBKXWRnyQLMXRwi104ezCRwf/Cx5G"
                            "HVowxNsr",
                        "smks": {}
                    },
                    "other_ik": "6keP/AwEpdZGfJAsxdHCLXTh7MJHB/8LHkYdWjDE2ys="
                },
                254614318: {
                    "super": {
                        "super": {
                            "super": None,
                            "root_chain": {
                                "length": 3,
                                "key": "B/loxMpW9NmrR7nmZOHbIbYVBBE/wA3+Ywd7zi2Rul0="
                            },
                            "own_key": {
                                "super": None,
                                "priv": "+P1pJdpLx7V9SLVSI/mR+WdDsa8doFRmWBmhbqk073s=",
                                "pub": "YvRzvBBEo8VpDPE1pyiHhx5eonTtIfwUp/egMuKkeC0="
                            },
                            "other_pub": {
                                "super": None,
                                "priv": None,
                                "pub": "kGMSCOcW8fI5Jpqi86PYyytw+JDE96pEjQOrLODTkXU="
                            }
                        },
                        "skr": {
                            "super": None,
                            "schain": {
                                "length": 0,
                                "key": "1qHExVTPmWhXXgZR5x2ZF6mYUZ/QB6/Bpv3lGmWsRiU="
                            },
                            "rchain": {
                                "length": 2,
                                "key": "izfEzNI8NC13k3UJVq8dM4d2hys4OTiTTXlYVfJi8Vo="
                            },
                            "prev_schain_length": 1
                        },
                        "ad":
                            "BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRiBc84+UOQFYdS1NbOEsA2Qu3UqAqMmJpjAgg0"
                            "4YfdoVdA",
                        "smks": {}
                    },
                    "other_ik": "zzj5Q5AVh1LU1s4SwDZC7dSoCoyYmmMCCDThh92hV0A="
                }
            },
            ALICE_BARE_JID: {
                1640101268: {
                    "super": {
                        "super": {
                            "super": None,
                            "root_chain": {
                                "length": 3,
                                "key": "VBc6DEauqdg3Rms0FrxXnYqXN+rJzYTBnF3bBtNQgNI="
                            },
                            "own_key": {
                                "super": None,
                                "priv": "qHZ3vHoGOYOSb4mA7SNdakPr4tPzavz3tDVUlJbl8Fc=",
                                "pub": "6hx93vhdZ5SU4dmn2/Vv6HZq7NQEukS18RXbgbpAanM="
                            },
                            "other_pub": {
                                "super": None,
                                "priv": None,
                                "pub": "ziV5pboN/FJDKd4CVAM5WZPoJ2piYPo2pVAHmy4cHS0="
                            }
                        },
                        "skr": {
                            "super": None,
                            "schain": {
                                "length": 0,
                                "key": "jtFIKe/WW151OqzCStFc4X12KU4Oh67LDukv3pOZRIg="
                            },
                            "rchain": {
                                "length": 1,
                                "key": "VjHTeYrE/udbYy6z3EphvL4gkxPzHfyIOAeA5DsNbSE="
                            },
                            "prev_schain_length": 1
                        },
                        "ad":
                            "BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRiBde4XMA5ywmeeVb3ZiNPHvbAoEAwDEz+y/P/"
                            "hA+3o+8N",
                        "smks": {}
                    },
                    "other_ik": "17hcwDnLCZ55VvdmI08e9sCgQDAMTP7L8/+ED7ej7w0="
                },
                1895030716: {
                    "super": {
                        "super": {
                            "super": None,
                            "root_chain": {
                                "length": 1,
                                "key": "+ZheXMs4YUirbou3sdBh5rBg8RsVunOJrSxmB4Ynvq4="
                            },
                            "own_key": {
                                "super": None,
                                "priv": "qBB/eunKyXjGW/RpH31oABtMNDynnpsYfu6egBN68Vg=",
                                "pub": "nbbbWUdYEN8YogMd8FKDZ+qlz2jAk7V0UuSm6e6gTxY="
                            },
                            "other_pub": {
                                "super": None,
                                "priv": None,
                                "pub": "i+VxR79cLM09i2KlKGBEUFDdK6UrrnMVE58J+BgMeSs="
                            }
                        },
                        "skr": {
                            "super": None,
                            "schain": {
                                "length": 1,
                                "key": "14XDd+3FyhkS0jSfYtYDIYVX0a+//3V/VcZd07yqd28="
                            },
                            "rchain": None,
                            "prev_schain_length": None
                        },
                        "ad":
                            "BaB8h0TC71J7q1nZtVdZf3psiYJHEdMyVhwHsLbZWRRiBea/qneH5GO9JWV486GPweRyxSrykVOK5AAt"
                            "Sl7PC4EC",
                        "smks": {}
                    },
                    "other_ik": "5r+qd4fkY70lZXjzoY/B5HLFKvKRU4rkAC1KXs8LgQI="
                }
            }
        }

        self.__active_devices: Dict[str, List[int]] = {
            BOB_BARE_JID: [ 543990483, 1746810996, 254614318 ],
            ALICE_BARE_JID: [ 1895030716, 1640101268, 276148623 ]
        }

        self.__inactive_devices: Dict[str, Dict[int, int]] = {
            BOB_BARE_JID: {},
            ALICE_BARE_JID: {}
        }

        self.__trust: Dict[str, Dict[int, Trust]] = {
            BOB_BARE_JID: {
                543990483: {
                    "key": "X19m8bd31UMY3lh6wUTNrzmRWDV+CFGDDZW58wHUOi8=",
                    "trusted": True
                },
                1746810996: {
                    "key": "6keP/AwEpdZGfJAsxdHCLXTh7MJHB/8LHkYdWjDE2ys=",
                    "trusted": True
                },
                254614318: {
                    "key": "zzj5Q5AVh1LU1s4SwDZC7dSoCoyYmmMCCDThh92hV0A=",
                    "trusted": True
                }
            },
            ALICE_BARE_JID: {
                1895030716: {
                    "key": "5r+qd4fkY70lZXjzoY/B5HLFKvKRU4rkAC1KXs8LgQI=",
                    "trusted": True
                },
                1640101268: {
                    "key": "17hcwDnLCZ55VvdmI08e9sCgQDAMTP7L8/+ED7ej7w0=",
                    "trusted": True
                }
            }
        }

        self.__jid_list: Optional[List[str]] = [ ALICE_BARE_JID, BOB_BARE_JID ]

    async def loadOwnData(self) -> Optional[OwnData]:
        return self.__own_data

    async def deleteOwnData(self) -> None:
        self.__own_data = None

    async def loadState(self) -> Optional[State]:
        return self.__state

    async def deleteState(self) -> None:
        self.__state = None

    async def loadSession(self, bare_jid: str, device_id: int) -> Optional[Session]:
        return self.__sessions.get(bare_jid, {}).get(device_id, None)

    async def deleteSession(self, bare_jid: str, device_id: int) -> None:
        self.__sessions.get(bare_jid, {}).pop(device_id, None)

    async def loadActiveDevices(self, bare_jid: str) -> Optional[List[int]]:
        return self.__active_devices.get(bare_jid, None)

    async def loadInactiveDevices(self, bare_jid: str) -> Optional[Dict[int, int]]:
        return self.__inactive_devices.get(bare_jid, None)

    async def deleteActiveDevices(self, bare_jid: str) -> None:
        self.__active_devices.pop(bare_jid, None)

    async def deleteInactiveDevices(self, bare_jid: str) -> None:
        self.__inactive_devices.pop(bare_jid, None)

    async def loadTrust(self, bare_jid: str, device_id: int) -> Optional[Trust]:
        return self.__trust.get(bare_jid, {}).get(device_id, None)

    async def deleteTrust(self, bare_jid: str, device_id: int) -> None:
        self.__trust.get(bare_jid, {}).pop(device_id, None)

    async def listJIDs(self) -> Optional[List[str]]:
        return self.__jid_list

    async def deleteJIDList(self) -> None:
        self.__jid_list = None
