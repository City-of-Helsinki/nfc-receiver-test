from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection


def connect_to_card():
    cardtype = AnyCardType()
    cardrequest = CardRequest(timeout=None, cardType=cardtype, newcardonly=True)
    print("Waiting for card insertion...")
    cardservice = cardrequest.waitforcard()

    cardservice.connection.connect()
    print("Card ATR: %s" % toHexString(cardservice.connection.getATR()))

    return cardservice


def select_application(card):
    print("Sending SELECT AID")
    SELECT = [0x00, 0xA4, 0x04,0x00, 0x0b, 0xf0,0x74,0x75,0x6e,0x6e,0x69,0x73,0x74,0x61,0x6d,0x6f, 0x00]
    response, sw1, sw2 = card.connection.transmit(SELECT, CardConnection.T1_protocol)
    print("Status: %02x %02x" % (sw1, sw2))
    assert len(response) == 0
    if sw1 != 0x90 or sw2 != 0x00:
        print("SELECT AID failed with 0x%02x%02x" % (sw1, sw2))
        return False
    return True


def send_client_id(card, client_id):
    client_id = bytes(client_id, encoding='ascii')
    EXTERNAL_AUTHENTICATE = [0x00, 0x82, 0x01, 0x01, len(client_id)]
    assert len(client_id) <= 256
    apdu = EXTERNAL_AUTHENTICATE + list(client_id)
    print("Sending EXTERNAL AUTHENTICATE: %s" % toHexString(apdu))
    response, sw1, sw2 = card.connection.transmit(apdu, CardConnection.T1_protocol)
    print("Status: %02x %02x" % (sw1, sw2))
    assert len(response) == 0


def get_token(card):
    print("Sending INTERNAL AUTHENTICATE")
    INTERNAL_AUTHENTICATE = [0x00, 0x88, 0x01, 0x01, 0x00]
    response, sw1, sw2 = card.connection.transmit(INTERNAL_AUTHENTICATE, CardConnection.T1_protocol)
    print("Status: %02x %02x" % (sw1, sw2))
    assert len(response) > 0

    loops = 0
    token = response
    while sw1 == 0x61:
        GET_RESPONSE = [0x00, 0xc0, 0x00, 0x00, sw2]
        print("Sending GET RESPONSE")
        response, sw1, sw2 = card.connection.transmit(GET_RESPONSE, CardConnection.T1_protocol)
        token += response
        loops += 1
        if loops > 10:
            raise Exception("Too many GET RESPONSE requests")

    return bytes(token)


while True:
    card = connect_to_card()
    if not select_application(card):
        continue
    send_client_id(card, 'a' * 50)
    token = get_token(card)
    del card
