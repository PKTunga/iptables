#!/bin/sh

# Define allowlist and blocklist files
files="/etc/ip-allowlist.conf /etc/domains-allowlist.conf /etc/ip-blocklist.conf /etc/domains-blocklist.conf"

# Ensure required files exist
for file in $files; do
    [ -f "$file" ] || sudo touch "$file"
    sudo chmod 644 "$file"
done

# Function to check and install iptables and netfilter-persistent if missing
install_iptables() {
    if ! command -v iptables >/dev/null 2>&1; then
        echo "iptables not found. Installing..."
        sudo apt update && sudo apt install -y iptables || sudo yum install -y iptables
    fi

    if ! command -v ip6tables >/dev/null 2>&1; then
        echo "ip6tables not found. Installing..."
        sudo apt update && sudo apt install -y iptables || sudo yum install -y iptables
    fi

    if ! dpkg -l | grep -q git; then
        echo "git not found. Installing..."
        sudo apt install -y git
    fi

    if ! dpkg -l | grep -q netfilter-persistent; then
        echo "netfilter-persistent not found. Installing..."
        sudo apt install -y netfilter-persistent iptables-persistent
        sudo systemctl enable netfilter-persistent
        sudo systemctl start netfilter-persistent
    fi

    if ! command -v apache2 >/dev/null 2>&1; then
        echo "Apache not found. Installing..."
        sudo apt install -y apache2 php libapache2-mod-php git
        sudo systemctl enable apache2
        sudo systemctl start apache2
    fi
}

# Ensure iptables and netfilter-persistent are installed and enabled
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
sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
sudo ip6tables-save | sudo tee /etc/iptables/rules.v6 > /dev/null

# Ensure rules are restored on reboot
echo "#!/bin/sh
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6" | sudo tee /etc/network/if-pre-up.d/iptables > /dev/null

sudo chmod +x /etc/network/if-pre-up.d/iptables

# Restart netfilter-persistent service to apply rules
sudo systemctl restart netfilter-persistent

echo "Allowlist updated, rules saved, and persistence enabled."


# Clone the PHP script from GitHub
cd /var/www/html
sudo git clone https://github.com/PKTunga/iptables.git .
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Configure Apache virtual host
echo "<VirtualHost *:80>
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>" | sudo tee /etc/apache2/sites-available/000-default.conf > /dev/null

# Restart Apache
sudo systemctl restart apache2

# Allow Apache to use iptables without password
if ! sudo grep -q "www-data ALL=(ALL) NOPASSWD: /sbin/iptables" /etc/sudoers; then
    echo "www-data ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee -a /etc/sudoers
fi

echo "Allowlist updated, rules saved, PHP script deployed, and persistence enabled."
