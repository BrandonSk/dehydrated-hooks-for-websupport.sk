#!/usr/bin/env bash

# This is a hook script for WEBSUPPORT.SK DNS API
# to be used along with the dehydrated letsencrypt client

# Websupport login information - enter here
  # Option 1 - Set api key (WS_USER) and secret (WS_PW) directly here
        WS_USER=""
        WS_PW=""
  # Option 2 - Store in file - specify path to the file with secrets here into WS_USER (example: ws_secrets)
  #            (the file needs permissions 400 and be owned by same user as the one running this script)
  #		${BASEDIR} is variable exported by the dehydrated.sh script
        WS_USER="${BASEDIR}/ws_secrets"

# Other user-defined variables
	RECORD_IDS_FILE="${BASEDIR}/ws_dns_challenge_record_IDs"	# Temporary file, where IDs of created records are stored
	SLEEP_SECONDS=3							# How many seconds to wait for propagation of records

# Websupport API variables - do not modify
        path="/v1/user/self"
        api="https://rest.websupport.sk"
        method=""       # Will be populated in the script based on $1 (phase)
        query=""        # Will be populated in the script based on domain name (e.g. /zone/DOMAINNAME/record)

# >>> See HOOKS section below for further options to customize this script <<<

# FUNCTIONS definitions
function _assign_secrets {
        [ ${i} -eq 1 ] && WS_USER="${1}"
        [ ${i} -eq 2 ] && WS_PW="${1}"
}

function _process_secrets_file {
        [ ! $(stat -c %u "${1}") -eq ${UID} ] && echo "Secrets file must be owned by user running this script!" && exit 2
        [ ! $(stat -c %a "${1}") -eq 600 ] && [ ! $(stat -c %a "${1}") -eq 400 ] \
                && echo "Secrets file not secure enough (permission 400 required)!" && exit 2
        local i=1
        while IFS='' read -r line || [ -n "$line" ]; do
                [ ${i} -gt 2 ] && break
                _assign_secrets "$line"
                i=$((i+1))
        done < "${1}"
}

function _hash_hmac {
        local digest="$1"
        local data="$2"
        local key="$3"
        shift 3
        echo -n "$data" | openssl dgst "-$digest" -hmac "$key" "$@"
}

function _parse_json {
        IFS=':{",}'
        local IDfound=0
        local recordID=0

        read -ra ADDR <<< "$1"
        for i in "${ADDR[@]}"; do
                if [ ! -z "$i" ]; then
                        if [ "${IDfound}" == "1" ]; then
                                recordID=$i
                                IDfound=2
                                break
                        else
                                [ "$i" == "id" ] && IDfound=1
                        fi
                fi
        done

        [ ${IDfound} -eq 2 ] && echo "${recordID}" || echo "NoID"
}

function buildJsonData {
        local s_d1='{"type":"TXT","name":"'
        local s_d2='","content":"'
        local s_d3='","ttl": 600}'
        echo "${s_d1}${1}${s_d2}${2}${s_d3}"
}

function _assign_secrets {
	# Assign secrets
  	# if secrets file exists, get info from file
        [ -f "${WS_USER}" ] && _process_secrets_file "${WS_USER}"
        apiKey="${WS_USER}"
        secret="${WS_PW}"
        [ "${WS_USER}" == "" -o "${WS_PW}" == "" ] && echo "API key and/or secret is missing. Quitting." && exit 3
}

# [][][][][][][][][][][][][][]
# []                        []
# []       H O O K S        []
# []                        []
# [][][][][][][][][][][][][][]

# Deploy_challenge and Clean_challenge are prepared for Websupport.sk API
# You may want to modify remaining hooks (e.g. deploy_cert) as you require,
# currently they perform no action.

# FUNCTIONS - Individual hooks based on actual phase

deploy_challenge() {
    # This hook is called once for every domain that needs to be
    # validated, including any alternative names you may have listed.
    #
    # Parameters:
    # - DOMAIN
    #   The domain name (CN or subject alternative name) being
    #   validated.
    # - TOKEN_FILENAME
    #   The name of the file containing the token to be served for HTTP
    #   validation. Should be served by your web server as
    #   /.well-known/acme-challenge/${TOKEN_FILENAME}.
    # - TOKEN_VALUE
    #   The token value that needs to be served for validation. For DNS
    #   validation, this is what you want to put in the _acme-challenge
    #   TXT record. For HTTP validation it is the value that is expected
    #   be found in the $TOKEN_FILENAME file.

    local fqdn="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    _assign_secrets

        DOMAIN=`sed -E 's/(.*)\.(.*\..*$)/\2/' <<< "${fqdn}"`
        SUBDOMAIN=${fqdn%"$DOMAIN"*}
        # Remove trailing dot (.) if present and * if present
        SUBDOMAIN="${SUBDOMAIN%.}"
        SUBDOMAIN="${SUBDOMAIN%*}"

        method="POST"
        query="/zone/${DOMAIN}/record"
        challenge_name="_acme-challenge.${SUBDOMAIN}"

        # Calculate signature
        signature=$(_hash_hmac "sha1" "${method} ${path}${query} $(date +%s)" "${secret}")
        signature=$(echo $signature | cut -d " " -f2)

        # Create record
        s_data=$(buildJsonData "${challenge_name}" "${TOKEN_VALUE}")
        response=$(curl -s "${api}${path}${query}" \
                        -H "Date: $(date +%Y%m%dT%H%M%SZ --utc)" \
                        -H "Accept: application/json" \
                        -H "Content-Type: application/json" \
                        -X "${method}" \
                        -d "${s_data}" \
                        -u "${apiKey}":"${signature}" \
                        )
        response=$(_parse_json "${response}")
        sleep $SLEEP_SECONDS

        # Output record ID to a file
        echo "${response}" >> "${RECORD_IDS_FILE}"
}

clean_challenge() {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.

    # Simple example: Use nsupdate with local named
    # printf 'server 127.0.0.1\nupdate delete _acme-challenge.%s TXT "%s"\nsend\n' "${DOMAIN}" "${TOKEN_VALUE}" | nsupdate -k /var/run/named/session.key

    local fqdn="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    _assign_secrets

        DOMAIN=`sed -E 's/(.*)\.(.*\..*$)/\2/' <<< "${fqdn}"`

        method="DELETE"
        # PARSE file with record IDs and delete each one
        if [ -f "${RECORD_IDS_FILE}" ]; then
                while read line
                do
                        query="/zone/${DOMAIN}/record/${line}"

                        # Calculate signature
                        signature=$(_hash_hmac "sha1" "${method} ${path}${query} $(date +%s)" "${secret}")
                        signature=$(echo $signature | cut -d " " -f2)

                        # Erase record
                        response=$(curl -s "${api}${path}${query}" \
                                        -H "Date: $(date +%Y%m%dT%H%M%SZ --utc)" \
                                        -X "${method}" \
                                        -u "${apiKey}":"${signature}" \
                                        )
                done < "${RECORD_IDS_FILE}"

                rm "${RECORD_IDS_FILE}"
        fi
}

sync_cert() {
    local KEYFILE="${1}" CERTFILE="${2}" FULLCHAINFILE="${3}" CHAINFILE="${4}" REQUESTFILE="${5}"

    # This hook is called after the certificates have been created but before
    # they are symlinked. This allows you to sync the files to disk to prevent
    # creating a symlink to empty files on unexpected system crashes.
    #
    # This hook is not intended to be used for further processing of certificate
    # files, see deploy_cert for that.
    #
    # Parameters:
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - REQUESTFILE
    #   The path of the file containing the certificate signing request.

    # Simple example: sync the files before symlinking them
    # sync "${KEYFILE}" "${CERTFILE}" "${FULLCHAINFILE}" "${CHAINFILE}" "${REQUESTFILE}"
}

deploy_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}" TIMESTAMP="${6}"

    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # - TIMESTAMP
    #   Timestamp when the specified certificate was created.

    # Simple example: Copy file to nginx config
    # cp "${KEYFILE}" "${FULLCHAINFILE}" /etc/nginx/ssl/; chown -R nginx: /etc/nginx/ssl
    # systemctl reload nginx
}

deploy_ocsp() {
    local DOMAIN="${1}" OCSPFILE="${2}" TIMESTAMP="${3}"

    # This hook is called once for each updated ocsp stapling file that has
    # been produced. Here you might, for instance, copy your new ocsp stapling
    # files to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - OCSPFILE
    #   The path of the ocsp stapling file
    # - TIMESTAMP
    #   Timestamp when the specified ocsp stapling file was created.

    # Simple example: Copy file to nginx config
    # cp "${OCSPFILE}" /etc/nginx/ssl/; chown -R nginx: /etc/nginx/ssl
    # systemctl reload nginx
}


unchanged_cert() {
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    # This hook is called once for each certificate that is still
    # valid and therefore wasn't reissued.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
}

invalid_challenge() {
    local DOMAIN="${1}" RESPONSE="${2}"

    # This hook is called if the challenge response has failed, so domain
    # owners can be aware and act accordingly.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - RESPONSE
    #   The response that the verification server returned

    # Simple example: Send mail to root
    # printf "Subject: Validation of ${DOMAIN} failed!\n\nOh noez!" | sendmail root
}

request_failure() {
    local STATUSCODE="${1}" REASON="${2}" REQTYPE="${3}" HEADERS="${4}"

    # This hook is called when an HTTP request fails (e.g., when the ACME
    # server is busy, returns an error, etc). It will be called upon any
    # response code that does not start with '2'. Useful to alert admins
    # about problems with requests.
    #
    # Parameters:
    # - STATUSCODE
    #   The HTML status code that originated the error.
    # - REASON
    #   The specified reason for the error.
    # - REQTYPE
    #   The kind of request that was made (GET, POST...)
    # - HEADERS
    #   HTTP headers returned by the CA

    # Simple example: Send mail to root
    # printf "Subject: HTTP request failed failed!\n\nA http request failed with status ${STATUSCODE}!" | sendmail root
}

generate_csr() {
    local DOMAIN="${1}" CERTDIR="${2}" ALTNAMES="${3}"

    # This hook is called before any certificate signing operation takes place.
    # It can be used to generate or fetch a certificate signing request with external
    # tools.
    # The output should be just the certificate signing request formatted as PEM.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain as specified in domains.txt. This does not need to
    #   match with the domains in the CSR, it's basically just the directory name.
    # - CERTDIR
    #   Certificate output directory for this particular certificate. Can be used
    #   for storing additional files.
    # - ALTNAMES
    #   All domain names for the current certificate as specified in domains.txt.
    #   Again, this doesn't need to match with the CSR, it's just there for convenience.

    # Simple example: Look for pre-generated CSRs
    # if [ -e "${CERTDIR}/pre-generated.csr" ]; then
    #   cat "${CERTDIR}/pre-generated.csr"
    # fi
}

startup_hook() {
  # This hook is called before the cron command to do some initial tasks
  # (e.g. starting a webserver).

  :
}

exit_hook() {
  local ERROR="${1:-}"

  # This hook is called at the end of the cron command and can be used to
  # do some final (cleanup or other) tasks.
  #
  # Parameters:
  # - ERROR
  #   Contains error message if dehydrated exits with error
}

HANDLER="$1"; shift
if [[ "${HANDLER}" =~ ^(deploy_challenge|clean_challenge|sync_cert|deploy_cert|deploy_ocsp|unchanged_cert|invalid_challenge|request_failure|generate_csr|startup_hook|exit_hook)$ ]]; then
  "$HANDLER" "$@"
fi
