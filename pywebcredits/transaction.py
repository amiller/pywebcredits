import json
import jsonld
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256


def parse_receipt_jsld(jsld):
    # A receipt is a  at the outer layer
    data = json.loads(jsld)
    assert 'tx' in data

    # Parse the inner data, check for idempotence
    assert data['tx'] == parse_transaction_jsld(json.dumps(data['tx']))


def parse_txbody(jsld):
    """
    A valid txbody...
      1. must contain a 'txnum'
      2. unless (txnum:0), must contain a reference to a previous receipt
      3. unless (txnum:0), must contain a reference
    """
    data = json.loads(jsld)
    txnum = data['txnum']
    assert type(txnum) is int
    assert txnum >= 0
    if txnum == 0:
        assert type(data['notary']) is unicode
        assert type(data['value']) is unicode
    else:
        assert type(data['prevdigest']) is unicode
        assert type(data['root']) is unicode
        assert type(data['pubkey']) is unicode
    assert type(data['recipient']) is unicode
    return data


def digest_for_tx(data):
    # Parse the inner body with the signature removed
    txbody = dict(data)
    txbody.pop('sig:signature')
    return jsonld.hexdigest(txbody)


def parse_transaction_jsld(jsld):
    data = json.loads(jsld)
    signature = long(data['sig:signature'])

    assert type(signature) is long

    # Parse the inner body with the signature removed
    txbody = dict(data)
    txbody.pop('sig:signature')
    assert txbody == parse_txbody(json.dumps(txbody))
    return data


def validate_transaction(tx, prevtx=None):
    if tx['txnum'] > 0:
        # Check the tx digest matches
        assert digest_for_tx(prevtx) == tx['prevdigest']

        # Check the pubkey matches the recipient digest
        pubkeydigest = prevtx['recipient'].split(':')[-1]
        assert SHA256.new(tx['pubkey']).hexdigest() == pubkeydigest

        # Validate the signature
        pubkey = RSA.importKey(tx['pubkey'])
        jsonld.validate(tx, pubkey)
