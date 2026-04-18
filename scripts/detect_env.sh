#!/bin/bash
detect_env() {
    OS=$(uname -s)
    if [ "$OS" = "Darwin" ]; then
        CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown")
        if   echo "$CHIP" | grep -qi "M4"; then echo "APPLE_M4"
        elif echo "$CHIP" | grep -qi "M2"; then echo "APPLE_M2"
        elif echo "$CHIP" | grep -qi "M1"; then echo "APPLE_M1"
        else echo "APPLE_INTEL"; fi
    elif [ "$OS" = "Linux" ]; then
        [ -e /dev/kvm ] && [ -r /dev/kvm ] && echo "LINUX_KVM" || echo "LINUX_NO_KVM"
    else echo "UNKNOWN"; fi
}
export NORIBEN_ENV=$(detect_env)
echo "[detect_env] Srodowisko: $NORIBEN_ENV"
