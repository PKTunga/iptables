#!/bin/sh

# Define allowlist and blocklist files
files="/etc/ip-allowlist.conf /etc/domains-allowlist.conf /etc/ip-blocklist.conf /etc/domains-blocklist.conf"

# Ensure required files exist
for file in $files; do
    [ -f "$file" ] || sudo touch "$file"
    sudo chmod 644 "$file"
done

# Function to check and install iptables if missing
install_iptables() {
    if ! command -v iptables >/dev/null 2>&1; then
        echo "iptables not found. Installing..."
        sudo apt update && sudo apt install -y iptables || sudo yum install -y iptables
        sudo systemctl enable iptables
        sudo systemctl start iptables
    fi

    if ! command -v ip6tables >/dev/null 2>&1; then
        echo "ip6tables not found. Installing..."
        sudo apt update && sudo apt install -y iptables || sudo yum install -y iptables
    fi
}

# Ensure iptables is installed and enabled
install_iptables

# Ensure iptables config directory exists
sudo mkdir -p /etc/iptables

# Define allowlist file
allowed_ips_file="/etc/ip-allowlist.conf"

# Create or clear the allowlist file
sudo sh -c "echo '# Allowed IPs' > $allowed_ips_file"

# Define IPv4 addresses and subnets
ipv4_ips="
102.213.241.211
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
"

# Define IPv6 addresses and subnets
ipv6_ips="
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
"

# Save IPv4 IPs to the allowlist file and add to iptables
for ip in $ipv4_ips; do
    echo "$ip" | sudo tee -a "$allowed_ips_file"
    sudo iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null || sudo iptables -A INPUT -s "$ip" -j ACCEPT
done

# Save IPv6 IPs to the allowlist file and add to ip6tables
for ip in $ipv6_ips; do
    echo "$ip" | sudo tee -a "$allowed_ips_file"
    sudo ip6tables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null || sudo ip6tables -A INPUT -s "$ip" -j ACCEPT
done

# Add default DROP rule for IPv4
sudo iptables -C INPUT -j DROP 2>/dev/null || sudo iptables -A INPUT -j DROP

# Add default DROP rule for IPv6
sudo ip6tables -C INPUT -j DROP 2>/dev/null || sudo ip6tables -A INPUT -j DROP


# Save rules for persistence
if [ ! -d "/etc/iptables" ]; then
    sudo mkdir /etc/iptables
    echo "Created /etc/iptables directory."
fi

sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6 > /dev/null

echo "Allowlist updated and rules saved."
