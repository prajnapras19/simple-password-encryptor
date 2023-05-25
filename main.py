#!/usr/bin/env python3
import subprocess
import sqlite3
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify, unhexlify
import sys
import getpass
import hashlib

DATABASE_NAME = 'password.db'

def copy_to_clipboard(data):
    subprocess.run("pbcopy", text=True, input=data)

def init():
    conn.execute('''CREATE TABLE IF NOT EXISTS password(
        name VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL
    );''')

def insert_password(name, password):
    conn.cursor().execute('INSERT INTO password(name, password) VALUES(?, ?);', [name, password])
    conn.commit()

def delete_password(name):
    conn.cursor().execute('DELETE FROM password WHERE name = ?;', [name])
    conn.commit()

def get_password(name):
    cur = conn.cursor()
    cur.execute('SELECT password FROM password WHERE name = ?;', [name])
    rows = cur.fetchall()
    return rows

def get_names():
    cur = conn.cursor()
    cur.execute('SELECT name FROM password order by name asc;')
    rows = cur.fetchall()
    return rows

def encrypt(pt: str, key: bytes):
    assert len(key) == 16
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = iv + cipher.encrypt(pad(pt.encode(), AES.block_size))
    return hexlify(ct)

def decrypt(ct: str, key: bytes):
    assert len(key) == 16
    tmp_ct = unhexlify(ct)
    iv = tmp_ct[:AES.block_size]
    real_ct = tmp_ct[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(real_ct), AES.block_size)
    return pt.decode()

def test_encrypt_decrypt():
    x = encrypt('abcdef', b'A' * 16)
    assert decrypt(x, b'A' * 16) == 'abcdef'

def menu_add():
    try:
        name = input('name: ')
        password = getpass.getpass('password: ')
        key = getpass.getpass('key to encrypt password: ')
        assert len(key) > 0 and len(name) > 0 and len(password) > 0
        
        hash_object = hashlib.sha256()
        hash_object.update(key.encode())
        password = encrypt(password, hash_object.hexdigest().encode()[:16])

        insert_password(name, password)
    
        print('password for "%s" saved successfully' % name)
    except:
        print('error on add password.')

def menu_names():
    try:
        names = get_names()
        if len(names) == 0:
            print('no password saved.')
        else:
            print('list of names:')
            for name in names:
                print(name[0])
    except:
        print('error on list names.')

def menu_get():
    try:
        name = input('name: ')
        key = getpass.getpass('key to decrypt password: ')
        assert len(name) > 0 and len(key) > 0
        
        hash_object = hashlib.sha256()
        hash_object.update(key.encode())
        password = get_password(name)[0]
        password = decrypt(password[0], hash_object.hexdigest().encode()[:16])
    
        copy_to_clipboard(password)
        
        print('password for "%s" copied to clipboard successfully' % name)
    except:
        print('error on get password.')

def menu_delete():
    try:
        name = input('name: ')
        delete_password(name)
        print('password for "%s" deleted successfully' % name)
    except:
        print('error on get password.')

def menu_help():
    print('usage: ./main.py (add|names|get|delete)')

if __name__ == '__main__':
    test_encrypt_decrypt()
    conn = sqlite3.connect(DATABASE_NAME)
    init()

    menu = {
        'add': menu_add,
        'names': menu_names,
        'get': menu_get,
        'delete': menu_delete,
    }

    if len(sys.argv) == 1 or (sys.argv[1] not in menu):
        menu_help()
    else:
        menu[sys.argv[1]]()

    conn.close()