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
