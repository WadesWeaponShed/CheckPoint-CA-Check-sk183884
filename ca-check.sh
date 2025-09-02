#!/usr/bin/env bash
set -euo pipefail

# --- prerequisites ---
for cmd in mgmt_cli jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is required but not found in PATH." >&2
    exit 1
  fi
done

############################################
# Section 1 - Trusted CAs
############################################
echo "Section 1: Checking Trusted Certificate Authorities..."

# Get all Trusted CA names
ca_names="$(mgmt_cli -r true show trusted-cas details-level "standard" -f json | jq -r '.objects[].name' || true)"

if [[ -z "${ca_names}" ]]; then
  echo "No Trusted CA objects were returned by the API."
  exit 0
fi

# Filter out exactly 'internal_ca'
mapfile -t other_cas < <(printf "%s\n" "$ca_names" | grep -v -E '^internal_ca$' | sed '/^$/d')

if (( ${#other_cas[@]} == 0 )); then
  echo "Result: Only 'internal_ca' found — you don't have any other certificate authorities."
  echo "Check Complete ✅"
  exit 0
else
  echo "Detected non-internal Trusted CA object(s):"
  for ca in "${other_cas[@]}"; do
    echo "- ${ca}"
  done
fi

############################################
# Section 2 - Gateways with VPN/Mobile Access
############################################
echo
echo "Section 2: Checking gateways for Site-to-Site VPN and Mobile Access blade status..."

# Collect gateways where either blade is enabled
gateways_output="$(
  mgmt_cli -r true show gateways-and-servers details-level "full" -f json \
  | jq -r '
    .objects[]
    | select(.type=="simple-gateway" or .type=="cluster" or .type=="cluster-member")
    | . as $gw
    | ( ($gw["network-security-blades"]["site-to-site-vpn"] // false) or ($gw["network-security-blades"]["mobile-access"] // false) ) as $hasAny
    | select($hasAny)
    | "- \($gw.name): Site-to-Site VPN=\(($gw["network-security-blades"]["site-to-site-vpn"] // false)), Mobile Access=\(($gw["network-security-blades"]["mobile-access"] // false))"
  ' || true
)"

if [[ -n "${gateways_output}" ]]; then
  echo "Gateways with relevant blades enabled:"
  printf "%s\n" "${gateways_output}"
  echo
  echo "Next steps:"
  echo "• Please review sk183884 to check if the non-internal certificate is a DigiCert CA."
  echo "• If it is, please verify the gateways listed above that are running Site-to-Site VPN or Mobile Access."
else
  echo "No gateways with Site-to-Site VPN or Mobile Access enabled were found."
  echo
  echo "Next steps:"
  echo "• Please review sk183884 to check if the non-internal certificate is a DigiCert CA."
  echo "• You currently have no gateways with Site-to-Site VPN or Mobile Access enabled to verify."
fi
