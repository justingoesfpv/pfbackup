# pfbackup
pfSense Firewall Configuration Backup Utility

Generate encrypted password with
>dotnet pfbackup.dll "password"

>pfbackup.exe "password"

## Example Config
###### pfbackup.config
```json
[
{
"RemoteHost": "192.168.1.1",
"RemotePort": 443,
"UseSSL": true,
"Username": "admin",
"Password": "encrypted_password",
"pfVersion": 0,
"BackupCopies": 30
}
]
```
Based loosely on: https://doc.pfsense.org/index.php/Remote_Config_Backup

pfVersion Values:
```
0 = 2.0.x through 2.2.5
1 = 2.2.6 through 2.3.2-p1
2 = 2.3.3 and Later
```
