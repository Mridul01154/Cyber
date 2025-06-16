#!/bin/bash

echo "================================="
echo " SENTINAL OS CLEANUP"
echo "================================="

echo "[*] Removing build output..."
rm -f ../build/sniffer.exe

rm -f ../src/*.o

echo "[*] Clearing logs..."
rm -f ../logs/*


rm -f ../core

echo "[+] Cleanup complete."
