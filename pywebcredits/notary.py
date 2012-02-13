import transaction as pywc
import jsonld


class Notary(object):
    def __init__(self, uri, privkey, store):
        self._uri = uri
        self._privkey = privkey
        self._store = store

    def post_transaction(self, jsld):
        try:
            tx = pywc.parse_transaction_jsld(jsld)
        except ValueError, e:
            return 400, "Could not parse tx", e  # Bad Request

        if tx['txnum'] == 0:
            # Accept a root tx if we're the designated notary
            assert tx['notary'] == self._uri
            rootdigest = pywc.digest_for_tx(tx)
        else:
            # Look up the root transaction
            rooturi = tx['root']
            rootdigest = rooturi.split(':')[-1]
            assert (rootdigest,0) in self._store

            # Look up the previous transaction
            prevdigest = tx['prevdigest']
            prevtx = self._store[(rootdigest, tx['txnum']-1)]['tx']
            assert pywc.digest_for_tx(prevtx) == prevdigest

            # Validate the relationship between tx and prevtx
            pywc.validate_transaction(tx, prevtx)

        # Sign the transaction
        rx = jsonld.sign({'tx': tx}, self._privkey)

        # Idempotent store
        assert (rootdigest,tx['txnum']) not in self._store or \
               rx == self._store[(rootdigest,tx['txnum'])]
        self._store[(rootdigest,tx['txnum'])] = rx

        return 200, rx
