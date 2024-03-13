#!/bin/bash
set -e

target=$1

log() {
    printf '[\033[96m%s\033[m] %s\n' '*' "$1"
}

log_question() {
    printf '[\033[95m%s\033[m] %s\n' '?' "$1"
}

log_success() {
    printf '[\033[92m%s\033[m] %s\n' '+' "$1"
}

log_warn() {
    printf '[\033[93m%s\033[m] %s\n' '!' "$1"
}

log_error() {
    printf '[\033[91m%s\033[m] %s\n' 'x' "$1"
}

is_linux() {
    if [[ $(uname) == "Linux" ]]; then
        return 0
    else
        return 1
    fi
}

get_linux_ditro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro=$NAME
        return 0
    elif type lsb_release >/dev/null 2>&1; then
        distro=$(lsb_release -si)
        return 0
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        distro=$DISTRIB_ID
        return 0
    elif [ -f /etc/debian_version ]; then
        distro=Debian
        return 0
    elif [ -f /etc/fedora-release ]; then
        distro=Fedora
        return 0
    elif [ -f /etc/centos-release ]; then
        distro=CentOS
        return 0
    else
        distro=Unknown
        return 1
    fi
}

install_pkg_with_apk() {
    log_success
    sudo apk -y update
    if [[ $target == "server" ]]; then
        sudo apk -y add git alpine-sdk cmake nasm mingw-w64-gcc protobuf-compiler openssl
    elif [[ $target == "client" ]]; then
        sudo apk -y add git alpine-sdk cmake nasm mingw-w64-gcc protobuf-compiler
    fi
}

install_pkg_with_apt() {
    sudo apt -y update
    if [[ $target == "server" ]]; then
        sudo apt -y install git build-essential cmake nasm g++-mingw-w64 protobuf-compiler openssl
    elif [[ $target == "client" ]]; then
        sudo apt -y install git build-essential cmake nasm g++-mingw-w64 protobuf-compiler
    fi
}

install_pkg_with_dnf() {
    sudo dnf -y check-update
    if [[ $target == "server" ]]; then
        sudo dnf -y groupinstall "Development Tools" "Development Libraries"
        sudo dnf -y install git cmake nasm mingw64-gcc-c++ protobuf-compiler openssl
    elif [[ $target == "client" ]]; then
        sudo dnf -y groupinstall "Development Tools" "Development Libraries"
        sudo dnf -y install git cmake nasm mingw64-gcc-c++ protobuf-compiler
    fi
}

install_pkg() {
    log "Installing packages..."

    if [[ $distro == "Alpine Linux" ]]; then
        if ! install_pkg_with_apk; then
            return 1
        fi
        return 0
    elif [[ $distro == "CentOS" ]] || [[ $distro == "Fedora" ]]; then
        if ! install_pkg_with_dnf; then
            return 1
        fi
        return 0
    elif [[ $distro == "Debian" ]] ||
        [[ $distro == "Ubuntu" ]] ||
        [[ $distro == "Kali"* ]] ||
        [[ $distro == "Parrot Security" ]]; then
        if ! install_pkg_with_apt; then
            return 1
        fi
        return 0
    else
        log_error "The linux distribution is not detected. Required packages cannot be installed."
        return 1
    fi
}

metasploit_exists() {
    log "Checking if the 'msfvenom' binary exists on the system..."

    if command -v msfvenom > /dev/null 2>&1; then
        return 0
    else return 1
    fi
}

golang_exists() {
    log "Checking if the 'go' binary exists on the system..."

    if command -v go > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

install_c2_server() {
    log "Install dependencies for the C2 server."

    if ! install_pkg; then
        log_error "Installing packages failed."
        exit 1
    fi

    if ! metasploit_exists; then
        log_error "Metasploit Framework does not exist on your system. Please install it by following the guide: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html"
        exit 1
    fi

    if ! golang_exists; then
        log_error "Golang does not exist on your system. Please install the latest version of Go."
        exit 1
    fi
}

install_c2_client() {
    log "Install dependencies for the C2 client."

    if ! install_pkg; then
        log_error "Installing packages failed."
        exit 1
    fi

    if ! golang_exists; then
        log_error "Golang does not exist on your system. Please install the latest version of Go."
        exit 1
    fi
}

if ! is_linux; then
    log_error "Your're running the program on non-Linux system. Hermit C2 is intended for Linux."
    log_error "Stop the installation."
    exit 1
fi

get_linux_ditro
if [[ $distro == "Unknown" ]]; then
    exit 1
fi
log "Linux Distribution: $distro"

if [[ $target == "server" ]]; then
    install_c2_server
elif [[ $target == "client" ]]; then
    install_c2_client
else
    log_error "Invalid target."
fi

log_success "Dependencies installed successfully."
exit 0