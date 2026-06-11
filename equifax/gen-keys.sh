#!/bin/sh
# Generate the throwaway SSH keypair the range uses for lateral movement
# (webserver -> database). These keys are NOT committed to git; run this once
# after cloning, before `docker compose build`.
#
#   sh equifax/gen-keys.sh
#
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
KEY="$DIR/webserver/ssh/id_rsa"

mkdir -p "$DIR/webserver/ssh"
rm -f "$KEY" "$KEY.pub"

# Lab-only keypair, no passphrase
ssh-keygen -t rsa -b 3072 -N "" -C "tomcat@equifax-lab" -f "$KEY"

# database trusts the webserver public key (this is what enables the lateral move)
cp "$KEY.pub" "$DIR/database/authorized_keys"
cp "$KEY.pub" "$DIR/database/id_rsa.pub"

echo "OK: range SSH keys generated. Now run: docker compose build"
