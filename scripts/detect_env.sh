#!/bin/bash
# Noriben SOC v6.6 — Auto environment detection
# Zwraca: APPLE_M1, APPLE_M2, APPLE_M4, LINUX_KVM, LINUX_NO_KVM

detect_env() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    if [ "$OS" = "Darwin" ]; then
        CHIP=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || system_profiler SPHardwareDataType | grep "Chip" | awk '{print $NF}')
        if echo "$CHIP" | grep -qi "M4"; then
            echo "APPLE_M4"
        elif echo "$CHIP" | grep -qi "M2"; then
            echo "APPLE_M2"
        elif echo "$CHIP" | grep -qi "M1"; then
            echo "APPLE_M1"
        else
            echo "APPLE_INTEL"
        fi
    elif [ "$OS" = "Linux" ]; then
        if [ -e /dev/kvm ] && [ -r /dev/kvm ]; then
            echo "LINUX_KVM"
        else
            echo "LINUX_NO_KVM"
        fi
    else
        echo "UNKNOWN"
    fi
}

export NORIBEN_ENV=$(detect_env)
echo "[detect_env] Środowisko: $NORIBEN_ENV"
