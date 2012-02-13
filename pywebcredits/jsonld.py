import json
import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256


def normalize(data):
    """
    Args: dict()
    Returns: a string of canonicalized json
    """
    # First check that it is json
    assert data == json.loads(json.dumps(data))

    # Fix this function with a proper json normalization for jsonld
    inner = ','.join(['"%s":%s' % (k,v) for k,v in sorted(data.items())])
    return '{' + inner + '}'


def hexdigest(data):
    norm = normalize(data)
    return SHA256.new(norm).hexdigest()


def sign(data, privkey):
    # Expecting an RSA private key
    assert privkey.can_sign()

    # Check the data isn't already signed
    assert 'sig:signature' not in data
    norm = normalize(data)
    sig = privkey.sign(SHA256.new(norm).digest(), None)[0]

    signed = dict(data)
    signed['sig:signature'] = sig
    return signed


def validate(data, publickey):
    # Expecting an RSA public key

    unsigned = dict(data)
    sig = unsigned.pop('sig:signature')

    norm = normalize(data)
    publickey.validate(SHA256.new(norm).digest(), (sig,))
