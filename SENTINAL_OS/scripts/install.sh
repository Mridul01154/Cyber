#!/bin/bash

echo "================================="
echo " SENTINAL OS INSTALLER"
echo "================================="

echo "[*] Creating build and logs directories if missing..."
mkdir -p ../build
mkdir -p ../logs

echo "[*] Compiling sniffer + detector + monitor..."
gcc ../src/sniffer.c ../src/detection.c ../src/logger.c ../src/proc_monitor.c -lwinmm -lwpcap -lws2_32 -mconsole -o ../build/sniffer.exe

if [ $? -eq 0 ]; then
    echo "[+] Compilation successful: ../build/sniffer.exe created"
else
    echo "[!] Compilation failed. Please check your code."
    exit 1
fi

echo "[*] Setting up default configs..."
if [ ! -f ../config/rules.config ]; then
    cp ../config/default_rules.config ../config/rules.config
    echo "[+] Default rules.config created"
fi

if [ ! -f ../config/proc_rules.config ]; then
    cp ../config/default_proc_rules.config ../config/proc_rules.config
    echo "[+] Default proc_rules.config created"
fi

if [ ! -f ../config/bad_hashes.txt ]; then
    cp ../config/default_bad_hashes.txt ../config/bad_hashes.txt
    echo "[+] Default bad_hashes.txt created"
fi

echo "[+] Installation complete. Run ../build/sniffer.exe to start."
