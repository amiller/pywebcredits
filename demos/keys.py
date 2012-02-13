import Crypto.PublicKey.RSA as RSA
import Crypto.Hash.SHA256 as SHA256
from config import HTTP_URL, HTTP_USER, HTTP_PASS
import requests
import json
import os


def pubkey_for_name(name):
    filename = '%s/keys/%s_pubkey.asc' % (os.path.dirname(__file__), name)
    return RSA.importKey(open(filename).read())


def privkey_for_name(name):
    filename = '%s/keys/%s_privkey.asc' % (os.path.dirname(__file__), name)
    return RSA.importKey(open(filename).read())


def pubkey_uri_for_name(name):
    pubkey = pubkey_for_name(name)
    pubhash = SHA256.new(pubkey.exportKey()).hexdigest()
    url = '%s/webcredits/key:%s:pubkey:%s' % (HTTP_URL, name, pubhash)
    return url


def privkey_uri_for_name(name):
    pubkey = pubkey_for_name(name)
    pubhash = SHA256.new(pubkey.exportKey()).hexdigest()
    url = '%s/webcredits/key:%s:privkey:%s' % (HTTP_URL, name, pubhash)
    return url


def generate_and_publish_key(name):
    # Generate the key
    key = RSA.generate(2048)
    privkey = key.exportKey()
    pubkey = key.publickey().exportKey()

    # Save to local files
    keydir = '%s/keys' % os.path.dirname(__file__)
    open('%s/%s_privkey.asc' % (keydir, name),'w').write(privkey)
    open('%s/%s_pubkey.asc' % (keydir, name),'w').write(pubkey)

    # Publish to a webserver
    def put(url, data):
        print url
        resp = requests.put(url,
                            auth=(HTTP_USER, HTTP_PASS),
                            data=json.dumps(data),
                            headers={'content-type': 'application/json'})
        assert resp.status_code == 201

    put(privkey_uri_for_name(name), {'privkey': privkey})
    put(pubkey_uri_for_name(name), {'pubkey': pubkey})
