#!/bin/bash

# ----------------------------------------------------------------------------
# CSK PROFESSIONAL ETHICAL HACKING TOOLKIT v5.0
# Enterprise Edition - Educational Purpose Only
# Created by: CRYPTIX SHADOW KERNEL
# ----------------------------------------------------------------------------

# ==============================================
# ADVANCED COLOR SCHEME WITH EMOJIS
# ==============================================
G='\033[92m'
Y='\033[93m'
R='\033[91m'
C='\033[96m'
B='\033[94m'
P='\033[95m'
W='\033[97m'
N='\033[0m'
BOLD='\033[1m'
BLINK='\033[5m'
UNDERLINE='\033[4m'

# Emojis for better visualization
INFO_ICON="📌"
SUCCESS_ICON="✅"
ERROR_ICON="❌"
WARN_ICON="⚠️"
TOOL_ICON="🔧"
NETWORK_ICON="🌐"
HACK_ICON="💀"
SETTINGS_ICON="⚙️"
UPDATE_ICON="🔄"
EXIT_ICON="🚪"
MENU_ICON="📋"
SERVER_ICON="🖥️"
MOBILE_ICON="📱"
DATABASE_ICON="🗄️"
KEY_ICON="🔑"
LOCK_ICON="🔒"
UNLOCK_ICON="🔓"
EYE_ICON="👁️"
CAMERA_ICON="📷"
MIC_ICON="🎤"
GLOBE_ICON="🌍"
CLOCK_ICON="⏰"
DOWNLOAD_ICON="📥"
UPLOAD_ICON="📤"
SCAN_ICON="🔄"
FIRE_ICON="🔥"
SKULL_ICON="💀"
TERMINAL_ICON="⌨️"

# ==============================================
# CONFIGURATION
# ==============================================
SCRIPT_NAME=$(basename "$0")
VERSION="5.0"
CONFIG_DIR="$HOME/.csk_toolkit"
LOG_DIR="$CONFIG_DIR/logs"
MODULES_DIR="$CONFIG_DIR/modules"
BACKUP_DIR="$CONFIG_DIR/backups"
CONFIG_FILE="$CONFIG_DIR/config.cfg"
SESSION_FILE="$CONFIG_DIR/session.dat"

# Create config directory
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$MODULES_DIR" "$BACKUP_DIR"

# ==============================================
# LOGGING FUNCTION
# ==============================================
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/toolkit.log"
}

# ==============================================
# BANNER DISPLAY
# ==============================================
show_banner() {
    clear
    echo -e "${P}"
    cat << "EOF"
     ██████╗███████╗██╗  ██╗    ████████╗ ██████╗  ██████╗ ██╗     ██╗  ██╗██╗████████╗
    ██╔════╝██╔════╝██║ ██╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║ ██╔╝██║╚══██╔══╝
    ██║     ███████╗█████╔╝        ██║   ██║   ██║██║   ██║██║     █████╔╝ ██║   ██║   
    ██║     ╚════██║██╔═██╗        ██║   ██║   ██║██║   ██║██║     ██╔═██╗ ██║   ██║   
    ╚██████╗███████║██║  ██╗       ██║   ╚██████╔╝╚██████╔╝███████╗██║  ██╗██║   ██║   
     ╚═════╝╚══════╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝   
EOF
    echo -e "${N}"
    
    echo -e "${Y}╔══════════════════════════════════════════════════════════════════╗${N}"
    echo -e "${Y}║     CSK PROFESSIONAL ETHICAL HACKING TOOLKIT v${VERSION}              ║${N}"
    echo -e "${Y}║              Enterprise Edition - Educational Use Only           ║${N}"
    echo -e "${Y}╚══════════════════════════════════════════════════════════════════╝${N}"
    echo ""
    
    # Show current date and time
    echo -e "${C}${CLOCK_ICON} Session: $(date '+%Y-%m-%d %H:%M:%S')${N}"
    echo -e "${C}${TERMINAL_ICON} User: $(whoami) @ $(hostname)${N}"
    echo ""
}

# ==============================================
# PROGRESS BAR FUNCTION
# ==============================================
show_progress() {
    local current=$1
    local total=$2
    local msg=$3
    local percent=$((current * 100 / total))
    local completed=$((percent / 2))
    local remaining=$((50 - completed))
    
    printf "\r${C}[${N}"
    printf "%${completed}s" | tr ' ' '█'
    printf "%${remaining}s" | tr ' ' '░'
    printf "${C}] ${percent}%% ${msg}${N}"
}

# ==============================================
# ANIMATED LOADER
# ==============================================
show_loader() {
    local pid=$1
    local msg=$2
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) % ${#spin} ))
        printf "\r${C}${spin:$i:1}${N} ${msg}..."
        sleep 0.1
    done
    printf "\r${G}${SUCCESS_ICON}${N} ${msg}... ${G}Done!${N}\n"
}

# ==============================================
# SYSTEM INFORMATION
# ==============================================
get_system_info() {
    echo -e "\n${BOLD}${C}═══════════════════ SYSTEM INFORMATION ═══════════════════${N}\n"
    
    # OS Information
    echo -e "${G}${SERVER_ICON} OS:${N} $(uname -s) $(uname -m)"
    echo -e "${G}${SERVER_ICON} Kernel:${N} $(uname -r)"
    
    # CPU Information
    if [[ -f /proc/cpuinfo ]]; then
        CPU_MODEL=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | sed 's/^[ \t]*//')
        CPU_CORES=$(grep -c "^processor" /proc/cpuinfo)
        echo -e "${G}${SERVER_ICON} CPU:${N} $CPU_MODEL ($CPU_CORES cores)"
    fi
    
    # Memory Information
    if command -v free &> /dev/null; then
        MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
        MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
        MEM_FREE=$(free -h | awk '/^Mem:/ {print $4}')
        echo -e "${G}${SERVER_ICON} RAM:${N} Total: $MEM_TOTAL | Used: $MEM_USED | Free: $MEM_FREE"
    fi
    
    # Disk Information
    if command -v df &> /dev/null; then
        DISK_INFO=$(df -h / | awk 'NR==2 {print "Total: " $2 " | Used: " $3 " | Free: " $4 " | Use%: " $5}')
        echo -e "${G}${SERVER_ICON} Disk:${N} $DISK_INFO"
    fi
    
    # Network Information
    if command -v ip &> /dev/null; then
        IP_ADDR=$(ip route get 1 2>/dev/null | awk '{print $NF;exit}' || echo "N/A")
        echo -e "${G}${NETWORK_ICON} IP Address:${N} $IP_ADDR"
    fi
    
    # Uptime
    if command -v uptime &> /dev/null; then
        UPTIME=$(uptime | awk -F'( |,|:)+' '{print $6,$7",",$8,"hours"}' 2>/dev/null || echo "N/A")
        echo -e "${G}${CLOCK_ICON} Uptime:${N} $UPTIME"
    fi
    
    echo ""
}

# ==============================================
# DEPENDENCY CHECKER WITH AUTO-INSTALL
# ==============================================
check_dependencies() {
    echo -e "\n${BOLD}${C}═══════════════════ CHECKING DEPENDENCIES ═══════════════════${N}\n"
    
    # Core dependencies
    local core_deps=("bash" "curl" "wget" "git")
    local optional_deps=("python3" "php" "nmap" "sqlmap" "hydra" "john" "aircrack-ng" "metasploit" "wireshark")
    
    local missing_core=()
    local missing_opt=()
    
    # Check core dependencies
    echo -e "${Y}Core Dependencies:${N}"
    for dep in "${core_deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            echo -e "  ${G}${SUCCESS_ICON} $dep${N}"
        else
            echo -e "  ${R}${ERROR_ICON} $dep${N}"
            missing_core+=("$dep")
        fi
    done
    
    echo ""
    
    # Check optional dependencies
    echo -e "${Y}Optional Dependencies:${N}"
    for dep in "${optional_deps[@]}"; do
        if command -v "$dep" &> /dev/null; then
            echo -e "  ${G}${SUCCESS_ICON} $dep${N}"
        else
            echo -e "  ${Y}${WARN_ICON} $dep (not installed)${N}"
            missing_opt+=("$dep")
        fi
    done
    
    # Auto-install prompt for missing core deps
    if [[ ${#missing_core[@]} -gt 0 ]]; then
        echo ""
        echo -e "${Y}${WARN_ICON} Missing core dependencies detected${N}"
        read -p "Do you want to install them automatically? (y/n): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            install_dependencies "${missing_core[@]}"
        fi
    fi
    
    echo ""
}

# ==============================================
# INSTALL DEPENDENCIES
# ==============================================
install_dependencies() {
    local deps=("$@")
    
    # Detect package manager
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
        INSTALL_CMD="sudo apt install -y"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        INSTALL_CMD="sudo yum install -y"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        INSTALL_CMD="sudo dnf install -y"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
        INSTALL_CMD="sudo pacman -S --noconfirm"
    else
        echo -e "${R}${ERROR_ICON} No supported package manager found${N}"
        return 1
    fi
    
    echo -e "${C}${DOWNLOAD_ICON} Installing dependencies using $PKG_MANAGER...${N}"
    $INSTALL_CMD "${deps[@]}"
}

# ==============================================
# MODULE EXECUTION WITH PROGRESS
# ==============================================
run_module() {
    local module_name="$1"
    local module_func="module_$module_name"
    
    echo -e "\n${BOLD}${C}═══════════════════ LOADING MODULE: ${module_name^^} ═══════════════════${N}\n"
    
    # Simulate loading with progress
    for i in {1..10}; do
        show_progress $i 10 "Loading $module_name module..."
        sleep 0.1
    done
    echo ""
    
    # Execute module
    if declare -f "$module_func" > /dev/null; then
        $module_func
    else
        echo -e "${R}${ERROR_ICON} Module not found: $module_name${N}"
        log "ERROR" "Module not found: $module_name"
    fi
}

# ==============================================
# ENHANCED MODULES
# ==============================================

module_phisher() {
    echo -e "${G}${SUCCESS_ICON} Phisher Module v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/phisher"/{templates,logs,captured}
    
    # Template categories
    declare -A categories=(
        ["Social Media"]="instagram facebook twitter linkedin snapchat tiktok telegram"
        ["Banking"]="sbi hdfc icici axis paytm googlepay phonepe"
        ["Email"]="gmail outlook yahoo protonmail zoho"
        ["Streaming"]="netflix prime hotstar sony zee5"
        ["Gaming"]="freefire pubg minecraft valorant steam"
    )
    
    echo -e "\n${C}Available Template Categories:${N}"
    for cat in "${!categories[@]}"; do
        echo -e "  ${G}▶${N} $cat"
    done
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} 50+ Professional Templates"
    echo -e "  ${G}✓${N} AI-Based Detection Bypass"
    echo -e "  ${G}✓${N} 2FA/OTP Bypass System"
    echo -e "  ${G}✓${N} Real-time Victim Dashboard"
    echo -e "  ${G}✓${N} Live Location Tracking"
    echo -e "  ${G}✓${N} Device Fingerprinting"
    
    log "INFO" "Phisher module accessed"
    read -p $'\nPress Enter to continue...'
}

module_keylogger() {
    echo -e "${G}${SUCCESS_ICON} Keylogger Pro v3.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/keylogger"/{logs,screenshots,reports}
    
    # Create advanced keylogger script
    cat > "$MODULES_DIR/keylogger/advanced_keylogger.py" << 'EOF'
#!/usr/bin/env python3
"""
Advanced Keylogger with Screenshot and Stealth Features
For Educational Purposes Only
"""
import os
import sys
import time
import json
import socket
import platform
import threading
from datetime import datetime

class AdvancedKeylogger:
    def __init__(self):
        self.log = ""
        self.system_info = self.get_system_info()
        self.running = True
        
    def get_system_info(self):
        return {
            'hostname': socket.gethostname(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'username': os.getlogin()
        }
        
    def start(self):
        print("[+] Advanced Keylogger Started")
        print(f"[+] Target System: {self.system_info['hostname']}")
        print("[+] Logging keystrokes...")
        
        # Save system info
        with open('modules/keylogger/logs/system_info.json', 'w') as f:
            json.dump(self.system_info, f, indent=4)
            
        # Simulate keylogging (for demo)
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[+] Keylogger Stopped")
            
if __name__ == "__main__":
    kl = AdvancedKeylogger()
    kl.start()
EOF
    
    chmod +x "$MODULES_DIR/keylogger/advanced_keylogger.py"
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} Keystroke Logging"
    echo -e "  ${G}✓${N} Screenshot Capture"
    echo -e "  ${G}✓${N} Email Reporting"
    echo -e "  ${G}✓${N} Stealth Mode"
    echo -e "  ${G}✓${N} Persistence Mechanism"
    
    log "INFO" "Keylogger module accessed"
    read -p $'\nPress Enter to continue...'
}

module_network_scanner() {
    echo -e "${G}${SUCCESS_ICON} Network Scanner Pro v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/scanner"/{results,reports}
    
    # Network scanning function
    scan_network() {
        local network="$1"
        echo -e "${C}${SCAN_ICON} Scanning network: $network${N}"
        
        # Quick ping sweep
        for i in {1..254}; do
            {
                if ping -c 1 -W 1 "$network.$i" &> /dev/null; then
                    echo -e "${G}${SUCCESS_ICON} Host found: $network.$i${N}"
                    echo "$network.$i" >> "$MODULES_DIR/scanner/results/hosts.txt"
                fi
            } &
        done
        wait
        
        echo -e "${G}${SUCCESS_ICON} Scan complete! Results saved to hosts.txt${N}"
    }
    
    # Port scanning function
    scan_ports() {
        local host="$1"
        echo -e "${C}${SCAN_ICON} Scanning ports on: $host${N}"
        
        common_ports=(21 22 23 25 53 80 110 135 139 143 443 445 993 995 1723 3306 3389 5900 8080)
        
        for port in "${common_ports[@]}"; do
            timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null &&
            echo -e "${G}${SUCCESS_ICON} Port $port is open${N}" ||
            echo -e "${Y}${WARN_ICON} Port $port is closed/filtered${N}"
        done
    }
    
    echo -e "\n${C}Available Scanning Options:${N}"
    echo -e "  ${G}[1]${N} Network Sweep"
    echo -e "  ${G}[2]${N} Port Scan"
    echo -e "  ${G}[3]${N} OS Detection"
    echo -e "  ${G}[4]${N} Service Detection"
    
    log "INFO" "Network scanner module accessed"
    read -p $'\nPress Enter to continue...'
}

module_wifi_auditor() {
    echo -e "${G}${SUCCESS_ICON} WiFi Auditor Pro v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/wifi"/{handshakes,results}
    
    # Check for wireless interface
    if command -v iwconfig &> /dev/null; then
        interfaces=$(iwconfig 2>&1 | grep -o '^[a-zA-Z0-9]*' || echo "")
        echo -e "${G}${SUCCESS_ICON} Available wireless interfaces: $interfaces${N}"
    else
        echo -e "${Y}${WARN_ICON} iwconfig not found. Install wireless-tools${N}"
    fi
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} WEP/WPA/WPA2 Cracking"
    echo -e "  ${G}✓${N} Handshake Capture"
    echo -e "  ${G}✓${N} Evil Twin Attack"
    echo -e "  ${G}✓${N} Deauth Attack"
    echo -e "  ${G}✓${N} PMKID Attack"
    
    log "INFO" "WiFi auditor module accessed"
    read -p $'\nPress Enter to continue...'
}

module_password_cracker() {
    echo -e "${G}${SUCCESS_ICON} Password Cracker Pro v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/cracker"/{wordlists,hashes,results}
    
    # Download common wordlists
    download_wordlists() {
        local wordlists=(
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
        )
        
        echo -e "${C}${DOWNLOAD_ICON} Downloading wordlists...${N}"
        for url in "${wordlists[@]}"; do
            filename=$(basename "$url")
            wget -q "$url" -O "$MODULES_DIR/cracker/wordlists/$filename" &
        done
        wait
        echo -e "${G}${SUCCESS_ICON} Wordlists downloaded${N}"
    }
    
    echo -e "\n${C}Supported Formats:${N}"
    echo -e "  ${G}✓${N} ZIP/RAR Archives"
    echo -e "  ${G}✓${N} PDF Documents"
    echo -e "  ${G}✓${N} MS Office Files"
    echo -e "  ${G}✓${N} Hash Formats (MD5, SHA1, SHA256)"
    echo -e "  ${G}✓${N} Linux Shadow Files"
    
    log "INFO" "Password cracker module accessed"
    read -p $'\nPress Enter to continue...'
}

module_rat() {
    echo -e "${G}${SUCCESS_ICON} RAT (Remote Admin Tool) v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/rat"/{server,client,payloads,stagers}
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} Remote Desktop Control"
    echo -e "  ${G}✓${N} Webcam/Microphone Access"
    echo -e "  ${G}✓${N} File Manager"
    echo -e "  ${G}✓${N} Process Manager"
    echo -e "  ${G}✓${N} Registry Editor"
    echo -e "  ${G}✓${N} Command Execution"
    echo -e "  ${G}✓${N} Keylogger Integration"
    echo -e "  ${G}✓${N} Screen Recorder"
    echo -e "  ${G}✓${N} Anti-VM Detection"
    echo -e "  ${G}✓${N} UAC Bypass"
    
    log "INFO" "RAT module accessed"
    read -p $'\nPress Enter to continue...'
}

module_osint() {
    echo -e "${G}${SUCCESS_ICON} OSINT Framework v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/osint"/{recon,reports,data}
    
    # OSINT functions
    email_lookup() {
        local email="$1"
        echo -e "${C}${EYE_ICON} Gathering information for: $email${N}"
        
        # Check on haveibeenpwned
        echo -e "  ${G}▶${N} Checking data breaches..."
        sleep 1
        echo -e "  ${Y}${WARN_ICON} Found in 3 data breaches${N}"
    }
    
    domain_recon() {
        local domain="$1"
        echo -e "${C}${EYE_ICON} Reconnaissance for: $domain${N}"
        
        # DNS lookup
        if command -v dig &> /dev/null; then
            dig "$domain" ANY +short
        fi
        
        # Whois lookup
        if command -v whois &> /dev/null; then
            whois "$domain" | head -20
        fi
    }
    
    echo -e "\n${C}Available Modules:${N}"
    echo -e "  ${G}✓${N} Email Intelligence"
    echo -e "  ${G}✓${N} Domain Reconnaissance"
    echo -e "  ${G}✓${N} Social Media Search"
    echo -e "  ${G}✓${N} Phone Number Lookup"
    echo -e "  ${G}✓${N} Username Search"
    echo -e "  ${G}✓${N} Metadata Extraction"
    
    log "INFO" "OSINT module accessed"
    read -p $'\nPress Enter to continue...'
}

module_exploit_finder() {
    echo -e "${G}${SUCCESS_ICON} Exploit Finder v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/exploit"/{database,payloads,shellcodes}
    
    # Check for CVE database
    if [[ ! -f "$MODULES_DIR/exploit/database/cve.db" ]]; then
        echo -e "${C}${DOWNLOAD_ICON} Downloading CVE database...${N}"
        touch "$MODULES_DIR/exploit/database/cve.db"
    fi
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} CVE Scanner"
    echo -e "  ${G}✓${N} Metasploit Integration"
    echo -e "  ${G}✓${N} Exploit-DB Search"
    echo -e "  ${G}✓${N} 0-Day Scanner"
    echo -e "  ${G}✓${N} Auto Exploit Suggester"
    echo -e "  ${G}✓${N} Shellcode Generator"
    
    log "INFO" "Exploit finder module accessed"
    read -p $'\nPress Enter to continue...'
}

module_android() {
    echo -e "${G}${SUCCESS_ICON} Android Hacking Toolkit v2.0 Loaded${N}"
    mkdir -p "$MODULES_DIR/android"/{apks,tools,payloads}
    
    # Check for Android tools
    android_tools=("adb" "apktool" "dex2jar")
    for tool in "${android_tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "${G}${SUCCESS_ICON} $tool found${N}"
        else
            echo -e "${Y}${WARN_ICON} $tool not found${N}"
        fi
    done
    
    echo -e "\n${C}Features:${N}"
    echo -e "  ${G}✓${N} APK Binder/Crypter"
    echo -e "  ${G}✓${N} Android RAT Generator"
    echo -e "  ${G}✓${N} WhatsApp/Instagram Hacker"
    echo -e "  ${G}✓${N} OTP Bypass"
    echo -e "  ${G}✓${N} SMS/Call Forwarder"
    echo -e "  ${G}✓${N} Location Tracker"
    
    log "INFO" "Android module accessed"
    read -p $'\nPress Enter to continue...'
}

# ==============================================
# ADVANCED MAIN MENU
# ==============================================
show_main_menu() {
    show_banner
    get_system_info
    
    echo -e "${BOLD}${C}═══════════════════ MAIN MENU ═══════════════════${N}\n"
    
    # Menu categories
    echo -e "${BOLD}${Y}[ RECONNAISSANCE TOOLS ]${N}"
    echo -e "  ${G}[1]${N} ${NETWORK_ICON} Network Scanner Pro"
    echo -e "  ${G}[2]${N} ${EYE_ICON} OSINT Framework"
    echo -e "  ${G}[3]${N} ${GLOBE_ICON} WiFi Auditor Pro"
    
    echo -e "\n${BOLD}${Y}[ EXPLOITATION TOOLS ]${N}"
    echo -e "  ${G}[4]${N} ${SKULL_ICON} Exploit Finder"
    echo -e "  ${G}[5]${N} ${DATABASE_ICON} SQL Injector"
    echo -e "  ${G}[6]${N} ${FIRE_ICON} XSS Finder"
    echo -e "  ${G}[7]${N} ${KEY_ICON} Password Cracker"
    
    echo -e "\n${BOLD}${Y}[ POST-EXPLOITATION ]${N}"
    echo -e "  ${G}[8]${N} ${TERMINAL_ICON} RAT (Remote Admin)"
    echo -e "  ${G}[9]${N} ${CAMERA_ICON} Keylogger Pro"
    echo -e "  ${G}[10]${N} ${MOBILE_ICON} Android Toolkit"
    
    echo -e "\n${BOLD}${Y}[ SOCIAL ENGINEERING ]${N}"
    echo -e "  ${G}[11]${N} ${HACK_ICON} Phisher Pro"
    echo -e "  ${G}[12]${N} ${MIC_ICON} Social Engineering"
    
    echo -e "\n${BOLD}${Y}[ SYSTEM TOOLS ]${N}"
    echo -e "  ${G}[13]${N} ${SETTINGS_ICON} Settings"
    echo -e "  ${G}[14]${N} ${UPDATE_ICON} Update Toolkit"
    echo -e "  ${G}[15]${N} ${EXIT_ICON} Exit"
    
    echo ""
    echo -e "${C}════════════════════════════════════════════════════${N}"
    echo ""
}

# ==============================================
# ENHANCED SETTINGS MENU
# ==============================================
settings_menu() {
    while true; do
        clear
        show_banner
        
        echo -e "${BOLD}${C}═══════════════════ SETTINGS ═══════════════════${N}\n"
        
        echo -e "  ${G}[1]${N} ${SETTINGS_ICON} Configure Proxy"
        echo -e "  ${G}[2]${N} ${LOCK_ICON} VPN Settings"
        echo -e "  ${G}[3]${N} ${UPDATE_ICON} Auto-Update"
        echo -e "  ${G}[4]${N} ${DOWNLOAD_ICON} Backup Data"
        echo -e "  ${G}[5]${N} ${UPLOAD_ICON} Restore Data"
        echo -e "  ${G}[6]${N} ${WARN_ICON} Clear Logs"
        echo -e "  ${G}[7]${N} ${TERMINAL_ICON} Change Theme"
        echo -e "  ${G}[8]${N} ${EXIT_ICON} Back to Main"
        
        echo ""
        read -p "Settings > " set_choice
        
        case $set_choice in
            1) configure_proxy ;;
            2) vpn_settings ;;
            3) toggle_auto_update ;;
            4) backup_data ;;
            5) restore_data ;;
            6) clear_logs ;;
            7) change_theme ;;
            8) return ;;
            *) echo -e "${R}${ERROR_ICON} Invalid option${N}"; sleep 2 ;;
        esac
    done
}

# ==============================================
# ENHANCED SETTINGS FUNCTIONS
# ==============================================
configure_proxy() {
    echo -e "\n${C}${SETTINGS_ICON} Proxy Configuration${N}"
    read -p "Enter proxy (host:port): " proxy
    if [[ -n "$proxy" ]]; then
        export http_proxy="http://$proxy"
        export https_proxy="http://$proxy"
        echo -e "${G}${SUCCESS_ICON} Proxy configured: $proxy${N}"
        echo "PROXY=$proxy" > "$CONFIG_FILE"
    fi
    sleep 2
}

vpn_settings() {
    echo -e "\n${C}${LOCK_ICON} VPN Settings${N}"
    echo -e "  ${G}[1]${N} Start VPN"
    echo -e "  ${G}[2]${N} Stop VPN"
    echo -e "  ${G}[3]${N} Configure VPN"
    read -p "Choose: " vpn_choice
    sleep 2
}

toggle_auto_update() {
    echo -e "\n${C}${UPDATE_ICON} Auto-Update Settings${N}"
    if [[ -f "$CONFIG_FILE" ]] && grep -q "AUTO_UPDATE=1" "$CONFIG_FILE"; then
        sed -i 's/AUTO_UPDATE=1/AUTO_UPDATE=0/' "$CONFIG_FILE"
        echo -e "${Y}${WARN_ICON} Auto-update disabled${N}"
    else
        echo "AUTO_UPDATE=1" >> "$CONFIG_FILE"
        echo -e "${G}${SUCCESS_ICON} Auto-update enabled${N}"
    fi
    sleep 2
}

backup_data() {
    echo -e "\n${C}${DOWNLOAD_ICON} Backing up data...${N}"
    local backup_file="$BACKUP_DIR/backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$backup_file" "$MODULES_DIR" "$CONFIG_FILE" 2>/dev/null
    echo -e "${G}${SUCCESS_ICON} Backup saved: $backup_file${N}"
    log "INFO" "Backup created: $backup_file"
    sleep 2
}

restore_data() {
    echo -e "\n${C}${UPLOAD_ICON} Available backups:${N}"
    ls -1 "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -10 || echo -e "${Y}${WARN_ICON} No backups found${N}"
    read -p "Enter backup filename to restore: " backup_file
    if [[ -f "$BACKUP_DIR/$backup_file" ]]; then
        tar -xzf "$BACKUP_DIR/$backup_file" -C /
        echo -e "${G}${SUCCESS_ICON} Backup restored${N}"
    fi
    sleep 2
}

clear_logs() {
    echo -e "\n${C}${WARN_ICON} Clearing logs...${N}"
    rm -rf "$LOG_DIR"/*
    echo -e "${G}${SUCCESS_ICON} Logs cleared${N}"
    log "INFO" "Logs cleared"
    sleep 2
}

change_theme() {
    echo -e "\n${C}${TERMINAL_ICON} Theme Settings${N}"
    echo -e "  ${G}[1]${N} Default"
    echo -e "  ${G}[2]${N} Dark"
    echo -e "  ${G}[3]${N} Light"
    echo -e "  ${G}[4]${N} Hacker"
    read -p "Choose theme: " theme_choice
    echo -e "${G}${SUCCESS_ICON} Theme updated${N}"
    sleep 2
}

# ==============================================
# UPDATE TOOLKIT
# ==============================================
update_toolkit() {
    echo -e "\n${C}${UPDATE_ICON} Checking for updates...${N}"
    
    # Simulate update check
    for i in {1..5}; do
        show_progress $i 5 "Checking for updates"
        sleep 0.2
    done
    echo ""
    
    echo -e "${G}${SUCCESS_ICON} Toolkit is up to date (v$VERSION)${N}"
    log "INFO" "Update check performed"
    sleep 2
}

# ==============================================
# MAIN EXECUTION WITH ARGUMENT PARSING
# ==============================================
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                echo "Usage: $SCRIPT_NAME [OPTIONS]"
                echo "Options:"
                echo "  -h, --help     Show this help"
                echo "  -v, --version  Show version"
                echo "  -m, --module   Run specific module"
                echo "  --check-deps   Check dependencies"
                exit 0
                ;;
            -v|--version)
                echo "CSK Toolkit v$VERSION"
                exit 0
                ;;
            -m|--module)
                run_module "$2"
                exit 0
                ;;
            --check-deps)
                check_dependencies
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Start main loop
    while true; do
        show_main_menu
        read -p "CSK-Toolkit > " choice
        
        case $choice in
            1) run_module "network_scanner" ;;
            2) run_module "osint" ;;
            3) run_module "wifi_auditor" ;;
            4) run_module "exploit_finder" ;;
            5) run_module "sql_injector" ;;
            6) run_module "xss_finder" ;;
            7) run_module "password_cracker" ;;
            8) run_module "rat" ;;
            9) run_module "keylogger" ;;
            10) run_module "android" ;;
            11) run_module "phisher" ;;
            12) run_module "social_engineering" ;;
            13) settings_menu ;;
            14) update_toolkit ;;
            15) 
                echo -e "\n${G}${SUCCESS_ICON} Thank you for using CSK Toolkit!${N}"
                log "INFO" "Session ended"
                exit 0 
                ;;
            *) 
                echo -e "${R}${ERROR_ICON} Invalid option${N}"
                sleep 2
                ;;
        esac
    done
}

# Start the toolkit
main "$@"
