#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
#  ubuntu-hardening.sh
#  Initial security hardening for a fresh Ubuntu server installation.
#  Must be run as root.
#
#  Usage (from GitHub — fresh server, curl may not be installed yet):
#    apt-get update -qq && apt-get install -y -qq curl && bash <(curl -fsSL https://raw.githubusercontent.com/omerdvd/UsefulScripts/refs/heads/main/ubuntu-hardening.sh)
#
#  Usage (if curl is already installed):
#    bash <(curl -fsSL https://raw.githubusercontent.com/omerdvd/UsefulScripts/refs/heads/main/ubuntu-hardening.sh)
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Colors & helpers
# ─────────────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[✓]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
ask()     { echo -e "${YELLOW}[?]${NC}    $*"; }

header() {
    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════${NC}"
    echo ""
}

yes_no() {
    # Usage: yes_no "Question?" && do_something
    local prompt="$1"
    local answer
    while true; do
        read -rp "$(echo -e "${YELLOW}[?]${NC}  $prompt [y/n]: ")" answer
        case "$answer" in
            [Yy]*) return 0 ;;
            [Nn]*) return 1 ;;
            *) warn "Please answer y or n." ;;
        esac
    done
}

# ─────────────────────────────────────────────────────────────────────────────
# Root check
# ─────────────────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root. Try: sudo bash <script>"

# ─────────────────────────────────────────────────────────────────────────────
# Ensure curl is installed (needed if script is run locally rather than piped)
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v curl &>/dev/null; then
    echo "curl not found — installing..."
    apt-get update -qq && apt-get install -y -qq curl
fi

# ─────────────────────────────────────────────────────────────────────────────
# Logging — tee all output (stdout + stderr) to a timestamped log file
# ─────────────────────────────────────────────────────────────────────────────
LOG_FILE="/tmp/ubuntu-hardening-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1
sleep 0.1  # allow tee subprocess to start before any output is written
echo "Logging to: $LOG_FILE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
clear
echo -e "${BOLD}${CYAN}"
cat <<'BANNER'
  ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
  ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║
  ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║
  ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║
  ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝
   ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝
         Ubuntu Server Hardening Script by omerdvd
BANNER
echo -e "${NC}"
echo "  This script will:"
echo "    1.  Create a non-privileged sudo user"
echo "    2.  Apply all system updates"
echo "    3.  Harden SSH (key + Google Authenticator 2FA)"
echo "    4.  Configure UFW firewall (SSH in only)"
echo "    5.  Install Google Authenticator"
echo "    6.  Install fail2ban"
echo "    7.  Enable automatic security updates"
echo "    8.  Apply sysctl network hardening"
echo "    9.  Set idle session timeout (10 minutes)"
echo "    10. Set server timezone"
echo "    11. Suppress login banner (hushlogin)"
echo "    12. Install fastfetch"
echo ""
echo -e "  ${RED}Run this on a fresh installation only.${NC}"
echo -e "  ${RED}Keep your current session open until you confirm SSH works.${NC}"
echo ""
read -rp "Press ENTER to continue or Ctrl+C to abort..."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — Collect all inputs up front
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 1 — Configuration"

# ── Username ──────────────────────────────────────────────────────────────────
while true; do
    read -rp "$(echo -e "${CYAN}[INPUT]${NC} Non-privileged username to create: ")" NEW_USER
    if [[ -z "$NEW_USER" ]]; then
        warn "Username cannot be empty."
    elif [[ "$NEW_USER" =~ [^a-z0-9_-] ]]; then
        warn "Use only lowercase letters, numbers, hyphens, or underscores."
    elif [[ "$NEW_USER" == "root" ]]; then
        warn "Cannot use 'root' as the username."
    else
        break
    fi
done

# ── Password ──────────────────────────────────────────────────────────────────
while true; do
    read -rsp "$(echo -e "${CYAN}[INPUT]${NC} Password for $NEW_USER (min 12 chars): ")" USER_PASS; echo
    read -rsp "$(echo -e "${CYAN}[INPUT]${NC} Confirm password: ")" USER_PASS2; echo
    if [[ "$USER_PASS" != "$USER_PASS2" ]]; then
        warn "Passwords do not match. Try again."
    elif [[ ${#USER_PASS} -lt 12 ]]; then
        warn "Password must be at least 12 characters."
    else
        break
    fi
done

# ── SSH Public Key ─────────────────────────────────────────────────────────────
echo ""
info "Paste the SSH public key for $NEW_USER."
info "It should start with: ssh-ed25519, ssh-rsa, or ecdsa-sha2-nistp256"
read -rp "$(echo -e "${CYAN}[INPUT]${NC} SSH public key: ")" SSH_PUB_KEY

if [[ -z "$SSH_PUB_KEY" ]]; then
    error "SSH public key cannot be empty — you will be locked out of the server."
fi

# Basic format validation
if ! echo "$SSH_PUB_KEY" | grep -qE '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+'; then
    warn "The key format looks unusual. Make sure it's a valid public key."
    yes_no "Continue anyway?" || error "Aborted. Please get the correct public key and re-run."
fi

# ── SSH Port ──────────────────────────────────────────────────────────────────
echo ""
read -rp "$(echo -e "${CYAN}[INPUT]${NC} SSH port [press ENTER for default: 22]: ")" SSH_PORT
SSH_PORT=${SSH_PORT:-22}
if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
    error "Invalid port: $SSH_PORT"
fi
if [[ "$SSH_PORT" == "22" ]]; then
    warn "Port 22 is the default — consider a non-standard port (e.g. 2222) to reduce automated scans."
fi

# ── Google Authenticator timing ───────────────────────────────────────────────
echo ""
echo -e "${CYAN}[?]${NC}   When do you want to configure Google Authenticator (2FA)?"
echo "      1) Now  — recommended, you'll scan the QR code during this script"
echo "      2) Later — installed, but you'll run 'google-authenticator' yourself later"
echo "                 NOTE: until configured, PAM uses 'nullok' so 2FA is skipped"
while true; do
    read -rp "$(echo -e "${CYAN}[INPUT]${NC} Choice [1/2]: ")" GA_CHOICE
    case "$GA_CHOICE" in
        1|2) break ;;
        *) warn "Please enter 1 or 2." ;;
    esac
done

# ── Timezone ──────────────────────────────────────────────────────────────────
echo ""
info "Current server timezone: $(timedatectl show --property=Timezone --value)"
info "Type part of a timezone name to search (e.g. 'Jerusalem', 'New_York', 'UTC', 'London')."
while true; do
    read -rp "$(echo -e "${CYAN}[INPUT]${NC} Timezone search: ")" TZ_SEARCH
    if [[ -z "$TZ_SEARCH" ]]; then
        warn "Search term cannot be empty."
        continue
    fi
    # Find matching timezones (case-insensitive)
    mapfile -t TZ_MATCHES < <(timedatectl list-timezones | grep -i "$TZ_SEARCH")
    if [[ ${#TZ_MATCHES[@]} -eq 0 ]]; then
        warn "No timezones matched '$TZ_SEARCH'. Try again (e.g. 'Asia/Jerusalem' or just 'Jerusalem')."
    elif [[ ${#TZ_MATCHES[@]} -eq 1 ]]; then
        TIMEZONE="${TZ_MATCHES[0]}"
        info "Found: $TIMEZONE"
        yes_no "Use $TIMEZONE?" && break || true
    else
        echo ""
        info "Multiple matches — pick one:"
        for i in "${!TZ_MATCHES[@]}"; do
            echo "    $((i+1))) ${TZ_MATCHES[$i]}"
        done
        echo ""
        while true; do
            read -rp "$(echo -e "${CYAN}[INPUT]${NC} Enter number [1-${#TZ_MATCHES[@]}]: ")" TZ_NUM
            if [[ "$TZ_NUM" =~ ^[0-9]+$ ]] && (( TZ_NUM >= 1 && TZ_NUM <= ${#TZ_MATCHES[@]} )); then
                TIMEZONE="${TZ_MATCHES[$((TZ_NUM-1))]}"
                break
            fi
            warn "Invalid choice."
        done
        break
    fi
done


IDLE_MINUTES=10

# ── Summary before applying ───────────────────────────────────────────────────
echo ""
header "Configuration Summary"
echo -e "  Username:              ${BOLD}$NEW_USER${NC}"
echo -e "  SSH port:              ${BOLD}$SSH_PORT${NC}"
echo -e "  Timezone:              ${BOLD}$TIMEZONE${NC}"
echo -e "  Google Auth (2FA):     ${BOLD}$([ "$GA_CHOICE" = "1" ] && echo "Configure now" || echo "Configure later")${NC}"
echo -e "  fail2ban:              ${BOLD}Yes${NC}"
echo -e "  Auto security updates: ${BOLD}Yes${NC}"
echo -e "  sysctl hardening:      ${BOLD}Yes${NC}"
echo -e "  Idle timeout:          ${BOLD}${IDLE_MINUTES} minutes${NC}"
echo ""
yes_no "Apply all settings now?" || error "Aborted by user."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — System Update
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 2 — System Update"
info "Updating package lists..."
apt-get update -qq
info "Upgrading installed packages (this may take a few minutes)..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq
info "Removing unnecessary packages..."
DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -qq
success "System is fully updated."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — Create User
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 3 — User: $NEW_USER"

if id "$NEW_USER" &>/dev/null; then
    warn "User $NEW_USER already exists. Skipping creation, updating password and groups."
else
    useradd -m -s /bin/bash "$NEW_USER"
    success "User $NEW_USER created."
fi

echo "$NEW_USER:$USER_PASS" | chpasswd
success "Password set for $NEW_USER."

usermod -aG sudo "$NEW_USER"
success "User $NEW_USER added to the sudo group."

# Suppress the default Ubuntu login message for both root and the new user
touch /root/.hushlogin
touch "/home/$NEW_USER/.hushlogin"
chown "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.hushlogin"
success "Login banner suppressed for root and $NEW_USER (hushlogin)."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — SSH Key Setup
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 4 — SSH Key Setup"

SSH_DIR="/home/$NEW_USER/.ssh"
AUTH_KEYS="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
echo "$SSH_PUB_KEY" >> "$AUTH_KEYS"   # append in case the file already exists
chmod 700 "$SSH_DIR"
chmod 600 "$AUTH_KEYS"
chown -R "$NEW_USER:$NEW_USER" "$SSH_DIR"

success "SSH public key added to $AUTH_KEYS"
success "Permissions set: .ssh/ = 700, authorized_keys = 600"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — Google Authenticator
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 5 — Google Authenticator"
apt-get install -y -qq libpam-google-authenticator
success "libpam-google-authenticator installed."

# Configure PAM for SSH (add TOTP, remove plain password challenge)
PAM_SSHD="/etc/pam.d/sshd"
cp "$PAM_SSHD" "${PAM_SSHD}.bak.$(date +%Y%m%d%H%M%S)"

# Disable the standard @include common-auth so PAM doesn't ask for a UNIX password
# (authentication is already handled by SSH pubkey + TOTP via keyboard-interactive)
sed -i 's/^@include common-auth/# @include common-auth  # disabled by ubuntu-hardening.sh/' "$PAM_SSHD"

# Add Google Authenticator PAM module if not already present
if ! grep -q "pam_google_authenticator" "$PAM_SSHD"; then
    echo "" >> "$PAM_SSHD"
    echo "# Google Authenticator TOTP — added by ubuntu-hardening.sh" >> "$PAM_SSHD"
    echo "auth required pam_google_authenticator.so nullok" >> "$PAM_SSHD"
fi

success "PAM configured to use Google Authenticator."

if [[ "$GA_CHOICE" == "1" ]]; then
    info "Starting Google Authenticator setup for $NEW_USER..."
    info "You will see a QR code — scan it with your Authenticator app."
    echo ""
    # Run google-authenticator as the new user (non-interactive flags for sane defaults)
    su - "$NEW_USER" -c "google-authenticator -t -d -f -r 3 -R 30 -W"
    echo ""
    success "Google Authenticator configured for $NEW_USER."
    info "2FA is now REQUIRED on every SSH login (after pubkey auth)."
else
    warn "Google Authenticator installed but NOT yet configured for $NEW_USER."
    info "To configure it later, SSH in as $NEW_USER and run:"
    echo ""
    echo "    google-authenticator"
    echo ""
    info "Until configured, the 'nullok' PAM flag skips 2FA."
    info "Once you run the setup command, 2FA becomes mandatory."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — SSH Hardening
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 6 — SSH Hardening"

# Back up the original config
SSHD_BACKUP="/etc/ssh/sshd_config.bak.$(date +%Y%m%d%H%M%S)"
cp /etc/ssh/sshd_config "$SSHD_BACKUP"
success "Original sshd_config backed up to: $SSHD_BACKUP"

# Write hardened sshd_config
cat > /etc/ssh/sshd_config <<EOF
# ══════════════════════════════════════════════════════════════════════════════
#  sshd_config — managed by ubuntu-hardening.sh
#  Generated: $(date)
# ══════════════════════════════════════════════════════════════════════════════

Include /etc/ssh/sshd_config.d/*.conf

# ── Network ───────────────────────────────────────────────────────────────────
Port $SSH_PORT
Protocol 2

# ── Logging ───────────────────────────────────────────────────────────────────
LogLevel VERBOSE

# ── Authentication ────────────────────────────────────────────────────────────
LoginGraceTime 1m
PermitRootLogin no
MaxAuthTries 6
MaxSessions 2

# Public key authentication
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Disable password authentication — keys + TOTP only
PasswordAuthentication no
PermitEmptyPasswords no

# Enable keyboard-interactive (used for Google Authenticator TOTP prompt)
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes

# Restrict login to the single admin user created by this script
AllowUsers $NEW_USER

# ── Forwarding / Tunneling — all disabled ─────────────────────────────────────
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no

# ── Session Keepalive ─────────────────────────────────────────────────────────
TCPKeepAlive no
ClientAliveInterval 300
ClientAliveCountMax 2

# ── Misc ──────────────────────────────────────────────────────────────────────
PrintMotd no
AcceptEnv LANG LC_*
UsePAM yes

# ── Subsystems ────────────────────────────────────────────────────────────────
Subsystem sftp /usr/lib/openssh/sftp-server

# ── Authentication chain ──────────────────────────────────────────────────────
EOF

# If GA was configured now, require pubkey + TOTP.
# If GA setup was deferred, use pubkey-only so the user can SSH in to run
# google-authenticator — they must manually enable the full chain afterwards.
if [[ "$GA_CHOICE" == "1" ]]; then
    echo "# Require SSH public key FIRST, then Google Authenticator TOTP code" >> /etc/ssh/sshd_config
    echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
else
    echo "# TOTP not yet configured — pubkey only until google-authenticator is set up." >> /etc/ssh/sshd_config
    echo "# After running 'google-authenticator' as $NEW_USER, change this line to:" >> /etc/ssh/sshd_config
    echo "#   AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
    echo "AuthenticationMethods publickey" >> /etc/ssh/sshd_config
fi

# /run/sshd must exist for sshd -t to pass on fresh installs
# (the directory is normally created when sshd starts for the first time)
mkdir -p /run/sshd

# Verify config before restarting
if sshd -t; then
    success "sshd_config syntax is valid."
else
    error "sshd_config has a syntax error! Restoring backup..."
    cp "$SSHD_BACKUP" /etc/ssh/sshd_config
    error "Original config restored. Please check the error above and re-run."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — UFW Firewall
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 7 — UFW Firewall"

apt-get install -y -qq ufw

# Reset to a clean state
ufw --force reset > /dev/null

# Defaults
ufw default deny incoming  > /dev/null
ufw default allow outgoing > /dev/null

# Allow only SSH
ufw allow "$SSH_PORT/tcp" comment "SSH (ubuntu-hardening.sh)"

# Enable firewall
ufw --force enable > /dev/null

success "UFW enabled."
success "Inbound:  only port $SSH_PORT (SSH) is allowed."
success "Outbound: all traffic allowed."
echo ""
ufw status verbose

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — fail2ban
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 8 — fail2ban"
apt-get install -y -qq fail2ban

# Write a local jail config for SSH
cat > /etc/fail2ban/jail.d/sshd-hardened.conf <<EOF
[sshd]
enabled  = true
port     = $SSH_PORT
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 4
bantime  = 1h
findtime = 10m
EOF

systemctl enable fail2ban > /dev/null
systemctl restart fail2ban
success "fail2ban installed and configured."
info "SSH jail: 4 failed attempts within 10 minutes = 1 hour ban."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — Automatic Security Updates
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 9 — Automatic Security Updates"
apt-get install -y -qq unattended-upgrades

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

systemctl enable unattended-upgrades > /dev/null
systemctl restart unattended-upgrades
success "Automatic security updates enabled (daily, no automatic reboots)."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — sysctl Network Hardening
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 10 — sysctl Network Hardening"

SYSCTL_CONF="/etc/sysctl.d/99-hardening.conf"

cat > "$SYSCTL_CONF" <<'EOF'
# ══════════════════════════════════════════════════════════════════════════════
#  sysctl hardening — managed by ubuntu-hardening.sh
# ══════════════════════════════════════════════════════════════════════════════

# ── IP Spoofing protection ────────────────────────────────────────────────────
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ── Block SYN flood attacks ───────────────────────────────────────────────────
net.ipv4.tcp_syncookies = 1

# ── Ignore ICMP redirects (prevents MITM routing attacks) ────────────────────
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# ── Ignore ICMP broadcast requests ───────────────────────────────────────────
net.ipv4.icmp_echo_ignore_broadcasts = 1

# ── Ignore bogus ICMP error responses ────────────────────────────────────────
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ── Do not accept source routing ─────────────────────────────────────────────
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ── Log suspicious packets (martians) ────────────────────────────────────────
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# ── Disable IPv6 if not needed ────────────────────────────────────────────────
# Uncomment the lines below only if you are certain you don't use IPv6:
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# ── Kernel pointer hiding ─────────────────────────────────────────────────────
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
EOF

sysctl -p "$SYSCTL_CONF" > /dev/null
success "sysctl network hardening applied from $SYSCTL_CONF"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — Idle Session Timeout
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 11 — Idle Session Timeout (${IDLE_MINUTES} minutes)"

IDLE_SECONDS=$(( IDLE_MINUTES * 60 ))

cat > /etc/profile.d/idle-timeout.sh <<EOF
# Auto-logout idle SSH sessions — set by ubuntu-hardening.sh
TMOUT=$IDLE_SECONDS
readonly TMOUT
export TMOUT
EOF

chmod 644 /etc/profile.d/idle-timeout.sh
success "Idle timeout set: sessions will be disconnected after ${IDLE_MINUTES} minutes of inactivity."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — Timezone
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 12 — Timezone"

timedatectl set-timezone "$TIMEZONE"
success "Timezone set to: $(timedatectl show --property=Timezone --value)"

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — fastfetch
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 13 — fastfetch"

apt-get install -y -qq fastfetch
success "fastfetch installed."

# Add fastfetch to /etc/skel/.bashrc so all future users get it automatically
FASTFETCH_LINE="fastfetch  # added by ubuntu-hardening.sh"
SKEL_BASHRC="/etc/skel/.bashrc"
if ! grep -q "fastfetch" "$SKEL_BASHRC" 2>/dev/null; then
    echo "" >> "$SKEL_BASHRC"
    echo "$FASTFETCH_LINE" >> "$SKEL_BASHRC"
fi

# Add to root's .bashrc
ROOT_BASHRC="/root/.bashrc"
if ! grep -q "fastfetch" "$ROOT_BASHRC" 2>/dev/null; then
    echo "" >> "$ROOT_BASHRC"
    echo "$FASTFETCH_LINE" >> "$ROOT_BASHRC"
fi

# Add to the new user's .bashrc
USER_BASHRC="/home/$NEW_USER/.bashrc"
if ! grep -q "fastfetch" "$USER_BASHRC" 2>/dev/null; then
    echo "" >> "$USER_BASHRC"
    echo "$FASTFETCH_LINE" >> "$USER_BASHRC"
fi

success "fastfetch added to .bashrc for root, $NEW_USER, and all future users."

# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 14 — Restart SSH
# ══════════════════════════════════════════════════════════════════════════════
header "SECTION 14 — Restarting SSH"

if sshd -t; then
    systemctl restart ssh
    success "SSH service restarted successfully."
else
    error "sshd_config test failed — SSH was NOT restarted. Check the config manually."
fi

# ══════════════════════════════════════════════════════════════════════════════
#  DONE — Final Summary
# ══════════════════════════════════════════════════════════════════════════════
SERVER_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ✓  Hardening Complete!${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}User:${NC}               $NEW_USER (sudo)"
echo -e "  ${BOLD}SSH port:${NC}           $SSH_PORT"
echo -e "  ${BOLD}Auth method:${NC}        $([ "$GA_CHOICE" = "1" ] && echo "SSH public key + Google Authenticator TOTP" || echo "SSH public key only (TOTP not yet configured)")"
echo -e "  ${BOLD}Root login:${NC}         Disabled"
echo -e "  ${BOLD}Password login:${NC}     Disabled"
echo -e "  ${BOLD}Firewall (UFW):${NC}        Active — inbound port $SSH_PORT only"
echo -e "  ${BOLD}fail2ban:${NC}              Active"
echo -e "  ${BOLD}Auto security updates:${NC} Active"
echo -e "  ${BOLD}sysctl hardening:${NC}      Applied"
echo -e "  ${BOLD}Idle timeout:${NC}          ${IDLE_MINUTES} minutes"
echo -e "  ${BOLD}Timezone:${NC}              $TIMEZONE"
echo -e "  ${BOLD}Login banner:${NC}          Suppressed (hushlogin)"
echo -e "  ${BOLD}fastfetch:${NC}             Installed"
echo ""
echo -e "  ${BOLD}SSH command to connect:${NC}"
echo -e "    ${CYAN}ssh -p $SSH_PORT $NEW_USER@$SERVER_IP${NC}"
echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  ⚠  IMPORTANT — Do this before closing this window:${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  1. Open a NEW terminal window (keep this one open!)"
echo "  2. SSH in as $NEW_USER on port $SSH_PORT"
echo "  3. Enter your TOTP code when prompted"
echo "  4. Run: sudo whoami  (should return 'root')"
if [[ "$GA_CHOICE" == "2" ]]; then
    echo ""
    echo -e "  ${YELLOW}⚠  2FA deferred — SSH currently uses pubkey only.${NC}"
    echo -e "  ${YELLOW}   To enable full pubkey + TOTP protection:${NC}"
    echo ""
    echo "     Step 1 — SSH in and set up Google Authenticator:"
    echo "       ssh -p $SSH_PORT $NEW_USER@$SERVER_IP"
    echo "       google-authenticator"
    echo ""
    echo "     Step 2 — Enable the full auth chain on the server:"
    echo "       sudo sed -i 's/^AuthenticationMethods publickey$/AuthenticationMethods publickey,keyboard-interactive/' /etc/ssh/sshd_config"
    echo "       sudo systemctl restart ssh"
    echo ""
    echo -e "  ${RED}  Do NOT close your session before confirming SSH still works after Step 2.${NC}"
fi
echo ""
echo -e "  ${RED}Only close this session after you confirm SSH login works.${NC}"
echo ""
echo -e "  ${BOLD}Full run log saved to:${NC}"
echo -e "    ${CYAN}$LOG_FILE${NC}"
echo ""
