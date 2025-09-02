Note: This script is a third-party utility, not an official Check Point tool. It is provided as-is for convenience and reporting purposes. Always verify results against official Check Point documentation and support resources before taking action.
.
# Check Point Certificate & VPN Blade Check Script

This script is designed to help Check Point administrators quickly assess the **Trusted Certificate Authorities (CAs)** configured in their environment and determine whether any gateways are running **Site-to-Site VPN** or **Mobile Access** blades.

## Features

- **Trusted CA Check**
  - Lists all Trusted CA objects in the Security Management Server.
  - Confirms if only the default `internal_ca` is present.
  - If other CAs exist, they are displayed for review.

- **Gateway Blade Check**
  - Runs only if a non-`internal_ca` is detected.
  - Identifies all gateways (simple-gateway, cluster, or cluster-member) with:
    - Site-to-Site VPN enabled
    - Mobile Access enabled
    - HTTPS Inspection enabled
  - Provides a summary of which blades are active per gateway.

- **Next Steps Guidance**
  - If a non-internal CA is found, the script advises reviewing [sk183884](https://support.checkpoint.com/results/sk/sk183884) to determine if the certificate is a DigiCert CA.
  - Lists affected gateways for quick follow-up.

## Requirements

- Run directly on the Check Point **Management Server**.


## Usage

1. Clone or download this repository.
2. Make the script executable:
   ```bash
   chmod +x ca-check.sh
