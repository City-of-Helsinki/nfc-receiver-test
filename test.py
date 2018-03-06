from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection


cardtype = AnyCardType()
while True:
    cardrequest = CardRequest(timeout=None, cardType=cardtype, newcardonly=True)
    print("Waiting for card insertion...")
    cardservice = cardrequest.waitforcard()

    print(cardservice)
    cardservice.connection.connect()
    print(toHexString(cardservice.connection.getATR()))

    print("Sending SELECT AID")
    SELECT = [0x00, 0xA4, 0x04,0x00, 0x0b, 0xf0,0x74,0x75,0x6e,0x6e,0x69,0x73,0x74,0x61,0x6d,0x6f, 0x00]
    response, sw1, sw2 = cardservice.connection.transmit(SELECT, CardConnection.T1_protocol)

    print(response)
    print("0x%02x" % sw1)
    print("0x%02x" % sw2)

    if sw1 != 0x90 or sw2 != 0x00:
        print("SELECT AID failed with 0x%02x%02x" % (sw1, sw2))

    print("Sending INTERNAL AUTHENTICATE")
    INTERNAL_AUTHENTICATE = [0x00, 0x88, 0x01, 0x01, 0x00,0x00]
    response, sw1, sw2 = cardservice.connection.transmit(INTERNAL_AUTHENTICATE, CardConnection.T1_protocol)
    print(response)
    print("0x%02x" % sw1)
    print("0x%02x" % sw2)
