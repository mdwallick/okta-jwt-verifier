import json
import sys

from .util.exceptions import *
from .jwt import JwtVerifier

def handler(event, context):
    # get the Bearer token from the authorization header
    jwt = event.authorizationToken

    try:
        oktaJwt = JwtVerifier()
        token = oktaJwt.decode(jwt)
        
        # Get principalId from the token
        principalId = token['sub']
        
        # check the scopes
        scopes = token['scp']
        

    except ValueError as err:
        # deny access if the token is invalid/expired/etc.
        print(err)
        return generatePolicy(None, 'Deny', event['methodArn'])
    
    return generatePolicy(principalId, 'Allow', event['methodArn'])

def generatePolicy(principalId, effect, methodArn):
    authResponse = {}
    authResponse['principalId'] = principalId
 
    if effect and methodArn:
        policyDocument = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'FirstStatement',
                    'Action': 'execute-api:Invoke',
                    'Effect': effect,
                    'Resource': methodArn
                }
            ]
        }
 
        authResponse['policyDocument'] = policyDocument
 
    return authResponse