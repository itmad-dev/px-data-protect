# REQUIREMENTS
#  request module
#
# SYNOPSIS
# Get keycloak access token, then list all backups found in all backup locations from a PX-Backup instance
#
# DESCRIPTION
# Sets Keycloak access token using PX-Backup login credentials, sends api request to list all backups in all backup locations.
#

import requests


payload = {
        "client_id": "pxcentral",
        "grant_type": "password",
        "username": "admin",
        "password": "[REDACTED]",
        "Content-Type": "application/x-www-form-urlencoded",
    }
# ip, fqdn of px-backup-ui svc
http = "http://px-backup-dr-apps-01.testco.local/auth/realms/master/protocol/openid-connect/token"
a = requests.post(http, data=payload)
a = a.json()
print(a['access_token'])

#test access_token
# ip, fqdn of px-backup svc
http2 = 'http://px-backup-rest-api-01.testco.local:10001/v1/backup/default'
header = {
    'Authorization': "Bearer " + a['access_token']
}
b = requests.request("GET", http2, headers=header)
b = b.json()
print(b)
