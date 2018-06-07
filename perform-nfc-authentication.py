import os
import datetime
import requests
from dotenv import load_dotenv
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.util import toHexString
from smartcard.CardConnection import CardConnection


load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))


class Settings:
    pass


settings = Settings()
settings.INTERFACE_DEVICE_ID = os.getenv('INTERFACE_DEVICE_ID')
settings.INTERFACE_DEVICE_SECRET = os.getenv('INTERFACE_DEVICE_SECRET')
settings.TUNNISTAMO_API_BASE = os.getenv('TUNNISTAMO_API_BASE', 'https://api.hel.fi/sso-test/')


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
    EXTERNAL_AUTHENTICATE = [0x00, 0x82, 0x01, 0x01, len(client_id) & 0xff]
    assert len(client_id) <= 256
    apdu = EXTERNAL_AUTHENTICATE + list(client_id)
    print("Sending EXTERNAL AUTHENTICATE: %s" % toHexString(apdu))
    response, sw1, sw2 = card.connection.transmit(apdu, CardConnection.T1_protocol)
    print("Status: %02x %02x" % (sw1, sw2))
    assert len(response) == 0
    if sw1 != 0x90 or sw2 != 0x00:
        raise Exception("Invalid response to EXTERNAL AUTHENTICATE: %02x %02x" % (sw1, sw2))


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

    if sw1 != 0x90 or sw2 != 0x00:
        raise Exception("Invalid response to INTERNAL AUTHENTICATE: %02x %02x" % (sw1, sw2))

    return bytes(token)


def perform_authentication(card):
    if not select_application(card):
        return False
    send_client_id(card, settings.INTERFACE_DEVICE_ID or ('a' * 16))
    token = get_token(card)
    token = str(token, encoding='ascii')
    print("Got token: %s" % token)
    return token


def read_identity(token):
    headers = {
        'Authorization': 'Bearer %s' % token,
        'X-Interface-Device-Secret': settings.INTERFACE_DEVICE_SECRET
    }
    resp = requests.get(settings.TUNNISTAMO_API_BASE + 'v1/user_identity/', headers=headers)
    if resp.status_code != 200:
        raise Exception("Unable to get user identities: %s" % str(resp.content, encoding='utf8'))
    data = resp.json()
    nonce = resp.headers.get('X-Nonce', None)
    for identity in data:
        print('Service %s: %s' % (identity['service'], identity['identifier']))
    return nonce


def get_pin(card, nonce):
    nonce_bytes = nonce.encode('ASCII')
    EXTERNAL_AUTHENTICATE = [0x00, 0x82, 0x01, 0x02, len(nonce)] + list(nonce_bytes)
    print('Sending EXTERNAL AUTHENTICATE with nonce {}'.format(nonce))
    response, sw1, sw2 = card.connection.transmit(EXTERNAL_AUTHENTICATE, CardConnection.T1_protocol)
    print("Status: %02x %02x" % (sw1, sw2))
    assert len(response) > 0
    if sw1 != 0x90 or sw2 != 0x00:
        raise Exception("Invalid response to EXTERNAL AUTHENTICATE: %02x %02x" % (sw1, sw2))
    print('Got PIN number {}'.format(bytes(response)))
    return response


if not settings.INTERFACE_DEVICE_ID or not settings.INTERFACE_DEVICE_SECRET:
    print("INTERFACE_DEVICE_ID or INTERFACE_DEVICE_SECRET not configured; using dummy values.")
    print("Tunnistamo API communication will not work.")


while True:
    card = connect_to_card()
    start = datetime.datetime.now()
    token = perform_authentication(card)
    if not token:
        continue
    diff = datetime.datetime.now() - start
    print("Card communication took %d ms" % (diff.seconds * 1000 + diff.microseconds / 1000))

    if not settings.INTERFACE_DEVICE_ID or not settings.INTERFACE_DEVICE_SECRET:
        continue

    start = datetime.datetime.now()
    nonce = read_identity(token)
    diff = datetime.datetime.now() - start
    print("Tunnistamo replied in %d ms" % (diff.seconds * 1000 + diff.microseconds / 1000))

    start = datetime.datetime.now()
    pin = get_pin(card, nonce)
    end = datetime.datetime.now()
    print("Got pin code in %d ms" % ((end-start).microseconds / 1000))
    del card
