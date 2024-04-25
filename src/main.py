import re
import base64
import os, sys
from time import sleep

from lib.stalwart import get_auth_code, get_access_token, get_acme_cert
from lib.crypto import get_chain_hash
from lib.cloudflare import get_zone_id, get_dns_record, create_dns_record, update_dns_record
from lib.logger import log, error

TLSA_TYPES = [3, 2]
PORTS = ["_25._tcp", "_465._tcp", "_587._tcp"]


def prepare_env():
    api_url = os.getenv("STALWART_URL")
    username = os.getenv("STALWART_USERNAME")
    password = os.getenv("STALWART_PASSWORD")
    zone = os.getenv("CLOUDFLARE_ZONE")
    hostname = os.getenv("HOSTNAME")
    cloudflare_token = os.getenv("CLOUDFLARE_API_TOKEN")

    if not api_url or not username or not password or not zone or not hostname or not cloudflare_token:
        error("Missing environment variable(s)")

        for env in ["STALWART_URL", "STALWART_USERNAME", "STALWART_PASSWORD", "CLOUDFLARE_ZONE", "HOSTNAME", "CLOUDFLARE_API_TOKEN"]:
            if not os.getenv(env):
                error(f"Missing: {env}")

        sys.exit(1)

    return api_url, username, password, zone, hostname


def run():
    log("Starting ...")
    api_url, username, password, zone, hostname = prepare_env()

    # Authenticate
    code = get_auth_code(api_url, username, password)
    if not code:
        error("Failed to get auth code")
        return

    access_token = get_access_token(api_url, code)
    if not access_token:
        error("Failed to get access token")
        return

    # Get certificate info from API
    cert = get_acme_cert(api_url, access_token)
    if not cert:
        error("Failed to get ACME cert")
        return

    cert = base64.b64decode(cert.encode() + b'==').decode("utf-8")
    match = [x.group() for x in re.finditer(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", cert, re.DOTALL)]

    if len(match) != 2:
        error("No certificates found.")
        return

    # TLSA type 3 (Chain) & # TLSA type 2 (CA)
    chain_hash = get_chain_hash(match[0])
    intermediate_hash = get_chain_hash(match[1])

    log(f"Chain hash: {chain_hash}")
    log(f"Intermediate hash: {intermediate_hash}")

    # Update DNS records, ...
    zone_id = get_zone_id(zone)
    if not zone_id:
        error("Failed to get zone ID")
        return

    for tlsa_type in TLSA_TYPES:
        cert_hash = tlsa_type == 3 and chain_hash or intermediate_hash

        for port in PORTS:
            record_name = f"{port}.{hostname}"
            record_value = {"usage": tlsa_type, "selector": 1, "matching_type": 1, "certificate": cert_hash}

            dns_record = get_dns_record(zone_id, record_name, tlsa_type)
            if not dns_record:
                log(f"No record found for {record_name}, creating the record ...")
                create_dns_record(zone_id, record_name, record_value)
                continue

            current_cert = dns_record["data"]["certificate"]
            if current_cert == cert_hash:
                log(f"{record_name} already up to date")
                continue

            log(f"Updating {record_name} (old: {dns_record['content']}) to {record_value}")

            # Update DNS record
            update_dns_record(zone_id, dns_record["id"], record_name, record_value)

    log("Done!")
    log("---------------------------------")


def main():
    run()

    # Run every 10 minutes, or some other interval depending on the environment variables
    timeout = int(os.getenv("TIMEOUT", 600))
    sleep(timeout)


if __name__ == '__main__':
    main()
