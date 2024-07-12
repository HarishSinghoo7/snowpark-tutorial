# Required package for snowflake
# pip install snowflake-snowpark-python

from snowflake.snowpark import Session
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization

connection_type = ''    # user_auth, sso_auth, rsa_auth

def user_auth_connection() -> Session:
    '''
    Connect with snowpark by using user authentication
    '''
    connection_param = {
        'ACCOUNT': '<account>',
        'USER': '<user>',
        'PASSWORD': '<password>',
        #[OPTIONAL]
        'ROLE': 'SYSADMIN',
        'WAREHOUSE': 'COMPUTE_WH',
        'DATABASE': 'SNOWPARK_TUTORIAL',
        'SCHEMA': 'LEARNING'
    }

    return Session.builder.configs(connection_param).create()


def sso_auth_connection() -> Session:
    '''
    Connect with snowpark by using Single Sign-On (sso) authentication
    '''
    connection_param = {
        'ACCOUNT': '<something.east-us-2.azure>',
        'USER': '<user_email>',
        'AUTHENTICATOR': 'externalbrowser'
    }

    return Session.builder.configs(connection_param).create()

def rsa_auth_connection() -> Session:
    '''
    Connect with snowpark by using private key authentication
    Follow steps mentioned in https://docs.snowflake.com/en/user-guide/key-pair-auth to setup RSA auth
    '''
    with open("./rsa_key.p8", "rb") as key:
        p_key= serialization.load_pem_private_key(
            key.read(),
            password=None, #os.environ['PRIVATE_KEY_PASSPHRASE'].encode(),
            backend=default_backend()
        )

    pkb = p_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    connection_param = {
        'ACCOUNT': '<account>',
        'USER': '<user>',
        'PRIVATE_KEY': pkb,
        #[OPTIONAL]
        'ROLE': 'SYSADMIN',
        'WAREHOUSE': 'COMPUTE_WH',
        'DATABASE': 'SNOWPARK_TUTORIAL',
        'SCHEMA': 'LEARNING'
    }

    return Session.builder.configs(connection_param).create()




connect_type = {
    'user_auth': 'Snowflake Connection By User Authentication',
    'rsa_auth': 'Snowflake Connection By RSA Authentication',
    'sso_auth': 'Snowflake Connection By SSO Authentication'
}

for type_, comment_ in connect_type.items(): 
    print('\n'*3,'-'*20, comment_, '-'*20)
    if type_ == 'user_auth':
        session = user_auth_connection()

    elif type_ == 'sso_auth':
        session = sso_auth_connection()

    elif type_ == 'rsa_auth':
        session = rsa_auth_connection()

    if session:
        print('\n\t Current account name: ', session.get_current_account())
        print('\t Current database name: ', session.get_current_database())
        print('\t Current schema name: ', session.get_current_schema())
        print('\t Current role name: ', session.get_current_role())
        print('\t Current warehouse name: ', session.get_current_warehouse())
    else:
        print(f'\n\t {type_} failed to connect: ')
