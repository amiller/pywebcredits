import pywebcredits.transaction as pywc
import pywebcredits.jsonld as jsonld
import pywebcredits.notary
from pywebcredits.notary import Notary
import json
from contextlib import contextmanager
import sys
import os

# Include keys from the demos path
sys.path += os.path.dirname(__file__)
import keys


# Create the notary using a temporary store (a dict)
# FIXME use a permanent store
notary = Notary(keys.pubkey_uri_for_name('test_notary_0'),
                keys.privkey_for_name('test_notary_0'),
                {})

# Load several keys to play with
alice_privkey = keys.privkey_for_name('alice')
bob_privkey = keys.privkey_for_name('bob')
carol_privkey = keys.privkey_for_name('carol')


def sign_txbody(txbody, privkey):
    assert txbody == pywc.parse_txbody(json.dumps(txbody))
    tx = jsonld.sign(txbody, privkey)
    jsonld.validate(tx, privkey.publickey())
    return tx


def transfer_token(prevtx, privkey, recipient):
    root = 'receipt:' + pywc.digest_for_tx(prevtx) if prevtx['txnum'] == 0 \
           else prevtx['root']
    txbody = dict(
        root=root,
        txnum=prevtx['txnum']+1,
        recipient=unicode(keys.pubkey_uri_for_name(recipient)),
        pubkey=unicode(privkey.publickey().exportKey()),
        prevdigest=unicode(pywc.digest_for_tx(prevtx)),
        )
    tx = sign_txbody(txbody, privkey)
    pywc.validate_transaction(tx, prevtx)
    return tx


# Create a root transaction, a credit issued by Alice to Bob
txbody_0 = dict(
    txnum=0,
    value='http://amiller.iriscouch.com/webcredits/token:one-beer-from-amiller',
    notary='https://amiller.iriscouch.com/webcredits/key:test_notary_0:pubkey:722460874262eb7c3d014d840d7d4050252e7ca10df93b0515401551bc71b489',
    recipient=keys.pubkey_uri_for_name('bob'),
    )
tx_0 = sign_txbody(txbody_0, alice_privkey)
resp, rx_0 = notary.post_transaction(json.dumps(tx_0))
assert resp == 200


# Transfer the token from Bob to Carol
tx_1 = transfer_token(rx_0['tx'], bob_privkey, 'carol')
resp, rx_1 = notary.post_transaction(json.dumps(tx_1))
assert resp == 200


# Transfer the token from Carol back to Alice
tx_2 = transfer_token(rx_1['tx'], carol_privkey, 'alice')
resp, rx_2 = notary.post_transaction(json.dumps(tx_2))
assert resp == 200
