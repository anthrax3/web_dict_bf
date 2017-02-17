
# Basic Web Dictionary Attack
A simple script that uses HTTP POST to attempt to authenticate to a given target.

# Usage

> python web_dict_attack.py [OPTIONS] <target>
[OPTIONS]
    -h  This help menu
    -u  Specify a filepath with a list of usernames to try -- one username per line
    -p  Specify a filepath with a list of passwords to try -- one password per line
    -t  Set the time between requests (in seconds)
    -U  Specify what the JSON user identifier is: Default is \'username\'
    -P  Specify what the JSON password identifier is: Default is \'password\'
    
Ex:

> python web_dict_attack.py -u /usr/share/ncrack/default.usr -p /usr/share/ncrack/default.pwd http://127.0.0.1/api/auth

# Requirements
Requirements are specified in requirements.txt

