#!/usr/bin/env bash
set -euo pipefail

# --- prerequisites ---
for cmd in mgmt_cli jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Error: '$cmd' is required but not found in PATH." >&2
    exit 1
  fi
done

run_checks_for_domain() {
  local domain="$1"

  echo
  echo "=============================================="
  echo "Domain: ${domain}"
  echo "=============================================="

  ############################################
  # Section 1 - Trusted CAs (per domain)
  ############################################
  echo "Section 1: Checking Trusted Certificate Authorities..."

  # Get all Trusted CA names in this domain
  ca_names="$(mgmt_cli -r true -d "$domain" show trusted-cas details-level "standard" -f json | jq -r '.objects[].name' || true)"

  if [[ -z "${ca_names}" ]]; then
    echo "No Trusted CA objects were returned by the API for this domain."
    echo "Check Complete ✅"
    return 0
  fi

  # Filter out exactly 'internal_ca'
  mapfile -t other_cas < <(printf "%s\n" "$ca_names" | grep -v -E '^internal_ca$' | sed '/^$/d')

  if (( ${#other_cas[@]} == 0 )); then
    echo "Result: Only 'internal_ca' found — you don't have any other certificate authorities."
    echo "Check Complete ✅"
    return 0
  else
    echo "Detected non-internal Trusted CA object(s):"
  fi

  any_digicert=false

  for ca in "${other_cas[@]}"; do
    echo "- ${ca}"

    # Resolve UID from opsec-trusted-cas first
    uid="$(mgmt_cli -r true -d "$domain" show opsec-trusted-cas -f json \
      | jq -r --arg n "$ca" '.objects[] | select(.name==$n) | .uid' || true)"

    # If not found, try external-trusted-cas (newer versions)
    if [[ -z "$uid" || "$uid" == "null" ]]; then
      uid="$(mgmt_cli -r true -d "$domain" show external-trusted-cas -f json 2>/dev/null \
        | jq -r --arg n "$ca" '.objects[]? | select(.name==$n) | .uid' || true)"
    fi

    dn=""
    if [[ -n "${uid:-}" && "$uid" != "null" ]]; then
      dn="$(mgmt_cli -r true -d "$domain" show generic-object uid "$uid" -f json | jq -r '.dn // empty' || true)"
    fi

    if [[ -n "$dn" ]]; then
      echo "  DN: $dn"
      if [[ "$dn" == *"DigiCert"* ]]; then
        any_digicert=true
        echo "⚠️  Warning: CA '${ca}' has DN containing DigiCert → please review sk183884."
      fi
    else
      echo "  DN: (not available via API)"
    fi
  done

  # If there are other CAs but none are DigiCert, stop here for this domain.
  if [[ "$any_digicert" == "false" ]]; then
    echo
    echo "Result: You have non-internal CA object(s), but none contain 'DigiCert' in the DN."
    echo "No DigiCert indicators found — gateway checks are not required."
    echo "Check Complete ✅"
    return 0
  fi

  ############################################
  # Section 2 - Gateways (per domain)
  ############################################
  echo
  echo "Section 2: Checking gateways for HTTPS Inspection, Site-to-Site VPN, and Mobile Access blade status..."

  # Pull the object list once for this domain
  objs_json="$(mgmt_cli -r true -d "$domain" show gateways-and-servers details-level "standard" -f json)"

  printf "%s" "$objs_json" | jq -r '
    .objects[]
    | select(.type=="simple-gateway" or .type=="cluster" or .type=="cluster-member" or .type=="simple-cluster")
    | [.type, .name] | @csv
  ' | while IFS=, read -r objtype name; do
    # Strip quotes around CSV fields
    objtype="${objtype//\"/}"
    name="${name//\"/}"

    # Map API "show" command by object type
    case "$objtype" in
      simple-gateway)          show_cmd="simple-gateway" ;;
      simple-cluster|cluster)  show_cmd="simple-cluster" ;;
      cluster-member)          show_cmd="cluster-member" ;;
      *) continue ;;
    esac

    # Fetch full object and print unified one-line summary
    if out="$(mgmt_cli -r true -d "$domain" show "$show_cmd" name "$name" details-level "full" -f json 2>/dev/null)"; then
      printf "%s" "$out" | jq -r '"\(.name): HTTPS=\(.["enable-https-inspection"] // false), S2S-VPN=\(
          (.["network-security-blades"]["site-to-site-vpn"]
           // (if (.vpn|type)=="object" then (.vpn.enabled // false) else (.vpn // false) end)
          )
        ), Mobile-Access=\(
          (.["network-security-blades"]["mobile-access"]
           // (if (."mobile-access"|type)=="object" then (.["mobile-access"].enabled // false) else (."mobile-access" // false) end)
          )
        )"'
    else
      echo "$name: (type $objtype) — unable to read details"
    fi
  done

  echo
  echo "Next steps:"
  echo "• If any non-internal CA was identified as DigiCert, you must follow the remediation steps in sk183884 to correct the issue."
  echo "• If any gateways above show HTTPS Inspection enabled, please also review sk183887 for required actions."
}

# ===========================
# MDS: enumerate domains
# ===========================
echo "Discovering domains on this Multi-Domain Server…"
# Pull all domains; skip Global domain(s)
mgmt_cli -r true show domains details-level "standard" -f json \
| jq -r '
  .objects[]
  | select((.domain-type // .type) != "Global")
  | .name
' | while read -r domain_name; do
  # Run checks per domain
  run_checks_for_domain "$domain_name"
done

echo
echo "All domains processed."
