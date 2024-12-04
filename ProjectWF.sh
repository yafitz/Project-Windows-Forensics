#! /bin/bash

#this script assumes you are running it from desktop and your main user name is kali if this is not true change lines 87,116,156.
#when promped for file to analyze enter the full path for script to function properly

#states the starting time of the script
START_TIME=$(date +"%Y-%m-%d %H:%M:%S")
echo "[*] Analysis started at: $START_TIME"

#!/bin/bash
#if you are not root it exists
if [ $(whoami) != "root" ]; then
echo "[*] This script requires root privileges to run. Please run it as root."
exit 1
fi

#continues here for root user
echo "[*] You are root. Proceeding with the script..."


#enter full path of the file you want to analyze
while true; do
read -p "[*] Choose the filename you want to analyze:" FILE
if [ -f $FILE ]; then
echo "[*] Grabbing $FILE..."
break #makes a loop if you enter invalid file name
else "[*] File does not exist. Please enter the correct file:"
fi
done
  
sudo apt update 
#makes an array for the tools needed and checks if they are installed
tools=("bulk-extractor" "binwalk" "foremost" "binutils")
function check_tool() {
tool=$1
if dpkg -s "$tool" &> /dev/null; then
echo "[+] $tool is already installed."
else
echo "[-] $tool is not installed."
install_tool "$tool" #calls on the next function after checking each tool to install it if missing
fi
}

function install_tool() {
tool=$1
retries=3 #tries 3 time to install tools if fails maybe if you have internet issues
for ((attempt=1; attempt<=retries; attempt++)); do
echo "[*] Installing $tool..."
sudo apt-get -y install "$tool"
if [ $? -eq 0 ]; then
echo "[+] $tool installed successfully."
return 0
else
echo "[-] Failed to install $tool. Retrying..."
sleep 2 
fi
done
echo "[-] Failed to install $tool after $retries attempts. Exiting..."
exit 1
}

#loops through the list of tools and check/install each one
for tool in "${tools[@]}"; do
    check_tool "$tool"
done

#checks if volatility directory exists and if not it gets volatility from github
function check/install_volatility () {
if [ ! -d "Volatility" ]; then
echo "[*] volatility not found. Cloning Volatility from GitHub..."
git clone https://github.com/yafitz/Volatility.git
cd Volatility
unzip volatility_2.6_lin64_standalone.zip
cd volatility_2.6_lin64_standalone
mv volatility_2.6_lin64_standalone vol
else
echo "[+] Volatility found. Skipping installation."
fi

}

check/install_volatility
#declares and makes the output directory for all the extracted data
OUTPUT_DIR="/home/kali/Desktop/Extracted_data"
mkdir -p "$OUTPUT_DIR"
#runs all the carvers on the given file and stores them in the output directory
echo "[*] Running different carvers to extract data"
echo "[*] Running foremost."
foremost "$FILE" -o "$OUTPUT_DIR/extracted_foremost"

echo "[*] Running bulk_extractor."
bulk_extractor -o "$OUTPUT_DIR/extracted_data" "$FILE"

echo "[*] Running binwalk."
binwalk "$FILE" > "$OUTPUT_DIR/binwalk.txt"
#checks if the packet.pcap file exists and if it does it gives you its location and size
pcap_file="$OUTPUT_DIR/extracted_data/packets.pcap"
if [ -f "$pcap_file" ]; then
echo "[*] Found network capture file: $pcap_file"
echo "[*] File size: $(du -h "$pcap_file" | cut -f1)"
else
echo "[*] No network capture file found."
fi
#uses strings tool to grab different human readable files and strings
echo "Checking for human readable files and strings"
hr=("exe" "password" "username" "http" "email" "dll" "html" "txt" "doc" "pdf")
for str in "${hr[@]}"; do
echo "[*] Searching for '$str' in $FILE:"
strings "$FILE" | grep -i "$str" | tee "$OUTPUT_DIR/$str.txt"
done
#uses volatility to check if the file has image profile and if it does stores it as a variable and runs different commands
function volatility() {
cd /home/kali/Desktop/Volatility/volatility_2.6_lin64_standalone
./vol -f $FILE imageinfo | tee "$OUTPUT_DIR/VolatilityInfo"
grep "Suggested Profile(s)" "$OUTPUT_DIR/VolatilityInfo" | {
awk -F'[:,]' '/Suggested Profile\(s\)/ && !/No suggestion/ {print $2}'
} | while IFS= read -r profile; do
profile=$(echo "$profile" | tr -d '[:space:]')
if [ -n "$profile" ]; then
echo "[*] Suggested profile found: $profile"
echo "[*] Running Volatility with profile: $profile"
./vol -f "$FILE" --profile="$profile" pslist | tee "$OUTPUT_DIR/VolatilityPSList"
./vol -f "$FILE" --profile="$profile" netscan | tee "$OUTPUT_DIR/VolatilityNetscan"
./vol -f "$FILE" --profile="$profile" printkey | tee "$OUTPUT_DIR/VolatilityPrintkey"
./vol -f "$FILE" --profile="$profile" dlllist | tee "$OUTPUT_DIR/VolatilityDLLlist"
./vol -f "$FILE" --profile="$profile" psscan | tee "$OUTPUT_DIR/VolatilityPSscan"
./vol -f "$FILE" --profile="$profile" pstree | tee "$OUTPUT_DIR/VolatilityPSTree"
else
echo "No Volatility Profiles found."
return 1
fi
done
}
volatility
#lists the number of files in the output directory
FOUND_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
echo "[*] Number of found files: $FOUND_FILES"
#lists the time the analysis is complete
END_TIME=$(date +"%Y-%m-%d %H:%M:%S")
echo "[*] Analysis completed at: $END_TIME"
#makes a report of all the files and directories gathered and stores it in output directory
REPORT_FILE="$OUTPUT_DIR/forensic_analysis_report_$(basename "$FILE").txt"
echo "[*] Creating report file: $REPORT_FILE"
echo "Forensic Analysis Report for $(basename "$FILE")" > "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"
echo "Analysis Start Time: $START_TIME" >> "$REPORT_FILE"
echo "Analysis End Time: $END_TIME" >> "$REPORT_FILE"
echo "Number of Found Files: $FOUND_FILES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
find "$OUTPUT_DIR/" -type f -o -type d >> "$REPORT_FILE"

#zips the extracted files
cd /home/kali/Desktop
echo "[*] Zipping extracted files and report..."
zip -r "extracted_data.zip" "$OUTPUT_DIR"
