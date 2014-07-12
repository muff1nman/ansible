#!/usr/bin/env python

from unittest import TestCase
import getpass
import os
import shutil
import time
import tempfile
from binascii import unhexlify
from binascii import hexlify
from nose.plugins.skip import SkipTest

#from ansible import errors
import ansible.errors
from ansible.utils.vault import *

# GPG IMPORTS
try:
    import gnupg
    HAS_GPG = True
except ImportError:
    HAS_GPG = False

class TestVaultGPG(TestCase):

    def setUp(self):
        print("Settingup")
        self.dirpath = tempfile.mkdtemp()
        shutil.rmtree(self.dirpath)
        shutil.copytree("vault_test_data", self.dirpath)
        C.VAULT_GPG_PUB_KEYRING = os.path.join(self.dirpath, "pubring.gpg")
        C.VAULT_GPG_PRIV_KEYRING = os.path.join(self.dirpath, "secring.gpg")
        C.VAULT_GPG_ALWAYS_TRUST = True # Test keyrings dont include a proper trustdb
        C.VAULT_GPG_RECIPIENTS = '0449DF12'


    def tearDown(self):
        print("tearing down")
        shutil.rmtree(self.dirpath)


    def test_methods_exist(self):
        v = VaultGPG()
        slots = ['keys_available',
                 'encrypt',
                 'decrypt',]
        for slot in slots:         
            assert hasattr(v, slot), "VaultGPG is missing the %s method" % slot


    def test_keys_as_none(self):
        if not HAS_GPG:
            raise SkipTest
        C.VAULT_GPG_RECIPIENTS = None
        v = VaultGPG()
        try:
            enc_data = v.encrypt("foobar",'ansible')
        except ansible.errors.AnsibleError:
            pass
        else:
            raise AssertionError


    def test_keys_as_empty_string(self):
        if not HAS_GPG:
            raise SkipTest
        C.VAULT_GPG_RECIPIENTS = ''
        v = VaultGPG()
        try:
            enc_data = v.encrypt("foobar",'ansible')
        except ansible.errors.AnsibleError:
            pass
        else:
            raise AssertionError


    def test_keys_as_foriegn_key(self):
        if not HAS_GPG:
            raise SkipTest
        # A foriegn key ID
        C.VAULT_GPG_RECIPIENTS = '12341234'
        v = VaultGPG()
        try:
            enc_data = v.encrypt("foobar",'ansible')
        except ansible.errors.AnsibleError:
            pass
        else:
            raise AssertionError


    def test_encrypt_decrypt_gpg(self):
        if not HAS_GPG:
            raise SkipTest
        v = VaultGPG()
        enc_data = v.encrypt("foobar",'ansible')
        dec_data = v.decrypt(enc_data,'ansible')
        assert enc_data != "foobar", "encryption failed"
        assert dec_data == "foobar", "decryption failed"


    def test_encrypt_decrypt_gpg_via_vault_lib(self):
        if not HAS_GPG:
            raise SkipTest
        v = VaultLib('ansible')
        v.cipher_name = "GPG"

        plain_text = """\
The world is moving so fast these days that the man who says it can't be done is
generally interrupted by someone doing it.
-- E. Hubbard"""
        enc_data = v.encrypt(plain_text)
        dec_data = v.decrypt(enc_data)
        assert enc_data != plain_text, "encryption failed"
        assert dec_data == plain_text, "decryption failed"


    def test_key_trust(self):
        if not HAS_GPG:
            raise SkipTest
        C.VAULT_GPG_RECIPIENTS = '0449DF12 659C181E'
        v = VaultGPG()
        # test always trusted
        enc_data = v.encrypt("foobar",'ansible')
        assert enc_data != "foobar", "encryption failed"
        # test untrusted keys fail
        v.alwaystrust = False # Test keyrings dont include a proper trustdb
        try:
            enc_data = v.encrypt("foobar",'ansible')
        except ansible.errors.AnsibleError:
            pass
        else:
            raise AssertionError
