#!/bin/bash

SDKMAN_DIR="/var/lib/qulog/.sdkman"

export SDKMAN_DIR
[[ -s "$SDKMAN_DIR/bin/sdkman-init.sh" ]] && source "$SDKMAN_DIR/bin/sdkman-init.sh"

journalctl -o json -f | /var/lib/qulog/.sdkman/candidates/jbang/current/bin/jbang /usr/local/bin/qulog.java journal
