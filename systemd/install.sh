#!/bin/bash

set -euo pipefail

# consts

SDK_DIR="/var/lib/qulog/.sdkman"
SDK_INIT="source $SDK_DIR/bin/sdkman-init.sh" 

# ask for sudo early (once)

sudo -v

# create qulog user if not yet created

create_user() {
  if ! id qulog &>/dev/null; then
    sudo useradd -r -s /usr/sbin/nologin -d /var/lib/qulog -m qulog
  fi
  if ! id -nG qulog | grep -qw systemd-journal; then
    sudo usermod -aG systemd-journal qulog
  fi
}

# install sdkman if not yet installed

install_sdkman() {
  if ! sudo -u qulog test -d "$SDK_DIR"; then
    sudo -u qulog bash -c 'curl -s "https://get.sdkman.io" | bash'
  fi
}

# install java 25, ignored if already installed

install_java() {
  if ! sudo -u qulog bash -c "$SDK_INIT && sdk current | grep -q java"; then
    sudo -u qulog bash "$SDK_INIT && sdk install java 25.0.1-open"
  fi
}

# install jbang, ignored if already installed

install_jbang() {
  if ! sudo -u qulog bash -c "$SDK_INIT && sdk current | grep -q jbang"; then
    sudo -u qulog bash -c "$SDK_INIT && sdk install jbang 0.132.1"
  fi
}

# copy binaries and setup

copy_binaries() {
  sudo mkdir -p /opt/qulog
  sudo cp -f qulog.java /opt/qulog/
  sudo cp -f systemd/qulog-start.sh /opt/qulog/
  sudo chown -R qulog:qulog /opt/qulog
  sudo chmod 755 /opt/qulog/qulog.java
  sudo chmod 755 /opt/qulog/qulog-start.sh
  sudo chmod +x /opt/qulog/qulog.java
  sudo chmod +x /opt/qulog/qulog-start.sh
}

# create symlink in /usr/local/bin

create_symlink() {
  sudo ln -sf /opt/qulog/qulog.java /usr/local/bin/qulog.java
  sudo ln -sf /opt/qulog/qulog.java /usr/local/bin/qulog
  sudo ln -sf /opt/qulog/qulog-start.sh /usr/local/bin/qulog-start.sh
}

# create config file

create_config() {
  sudo mkdir -p /etc/qulog
  sudo chown -R qulog:qulog /etc/qulog
  sudo chmod 755 /etc/qulog
  if ! sudo test -f /etc/qulog/qulog.cfg; then
    sudo cp -f systemd/qulog.cfg /etc/qulog/qulog.cfg
    sudo cp -f rules-sample.js /etc/qulog/rules.js
  fi
}

# setup systemd service

setup_systemd() {
  sudo cp -f systemd/qulog.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable qulog.service
  sudo systemctl restart qulog.service
}

# installation steps

echo "Creating qulog user"    && create_user
echo "Installing SDKMAN"      && install_sdkman
echo "Installing OpenJDK 25"  && install_java
echo "Installing JBang"       && install_jbang
echo "Copying binaries"       && copy_binaries
echo "Creating symlink"       && create_symlink
echo "Creating configuration" && create_config
echo "Setting up systemd"     && setup_systemd

echo "Done."
