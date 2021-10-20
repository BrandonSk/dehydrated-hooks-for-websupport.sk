# dehydrated-hooks-for-websupport.sk
Websupport.sk API hooks for the dehydrated.sh script for generation and renewal of letsencrypt certificates.

This hook script allows for generating letsencrypt certificates using DNS challenge for provider websupport.sk
You will need the dehydrated.sh client for letsencrypt (see https://dehydrated.io)

How to:
1) Place files into directory where your dehydrated.sh script is installed. The hook script needs to be in the hook subfolder (changeable in config).
2) Modify ws_secrets file to hold your api key and api secret. Change permission of the file to 400.
3) Modify the domains.txt file to reflect domains your certificate will cover.
4) Modify "config" file - mostly review/update options, which are uncommented. For other options refer to dehydrated documentation.
5) Finally, edit the actual hook script in the hook subdirectory. Editable options are at the beginning of the file.
6) (optional) If you want to, you may modify other hooks according to your needs. There are several other hooks when the script gets called (e.g. after new certificates are deplyed, etc.) where you may want to run your custom tasks (restart servers, proxies, etc.)

The CONFIG file by default holds the CA="letsencrypt-test" certification authority, so that you do not lock yourself out while testing the script. Once you are ready, change the CA to production: CA="letsencrypt"

The hook script creates necessary DNS TXT records at websupport.sk and once they are validated the script will erases them, keeping your DNS nice and tidy.

Enjoy.
