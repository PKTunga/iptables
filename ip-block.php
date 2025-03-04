<?php

// Configuration
$allowed_ips_file = '/etc/ip-allowlist.conf';
$allowed_domains_file = '/etc/domains-allowlist.conf';
$blocked_ips_file = '/etc/ip-blocklist.conf';
$blocked_domains_file = '/etc/domains-blocklist.conf';
$iptables_v4 = '/etc/iptables/rules.v4';
$iptables_v6 = '/etc/iptables/rules.v6';

// Get the visitor's IP
$visitor_ip = $_SERVER['REMOTE_ADDR'];

// Read allowlist and blocklist
$allowed_ips = file_exists($allowed_ips_file) ? file($allowed_ips_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
$blocked_ips = file_exists($blocked_ips_file) ? file($blocked_ips_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];


// Function to check and add rules to iptables
function add_rule_if_missing($ip, $action, $protocol = "IPv4") {
    $iptables_cmd = ($protocol === "IPv6") ? "ip6tables" : "iptables";

    // Check if the rule exists before adding it
    $check_rule = shell_exec("sudo $iptables_cmd -C INPUT -s $ip -j $action 2>&1");
    if (strpos($check_rule, 'No chain/target') !== false || strpos($check_rule, 'Bad rule') !== false) {
        shell_exec("sudo $iptables_cmd -A INPUT -s $ip -j $action");
    }
}



// Ensure allowed IPs are accepted
foreach ($allowed_ips as $ip) {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        add_rule_if_missing($ip, "ACCEPT", "IPv6");
    } else {
        add_rule_if_missing($ip, "ACCEPT", "IPv4");
    }
}

// Block non-allowed IPs
if (!in_array($visitor_ip, $allowed_ips)) {
    if (filter_var($visitor_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        add_rule_if_missing($visitor_ip, "DROP", "IPv6");
    } else {
        add_rule_if_missing($visitor_ip, "DROP", "IPv4");
    }

    // Send 403 Forbidden response
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied: Your IP ' . $visitor_ip . ' is not allowed.');
}

// Save iptables rules for persistence
shell_exec("sudo iptables-save | sudo tee $iptables_v4 > /dev/null");
shell_exec("sudo ip6tables-save | sudo tee $iptables_v6 > /dev/null");


// Ensure all allowed IPs are added to iptables
foreach ($allowed_ips as $ip) {
    shell_exec("sudo iptables -A INPUT -s $ip -j ACCEPT");
}

// Enforce default block for all IPs except those in allowlist
if (!in_array($visitor_ip, $allowed_ips)) {
    shell_exec("sudo iptables -A INPUT -s $visitor_ip -j DROP");
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied: Your IP ' . $visitor_ip . ' is not allowed.');

}

// Additionally block manually listed IPs
if (in_array($visitor_ip, $blocked_ips)) {
    shell_exec("sudo iptables -A INPUT -s $visitor_ip -j DROP");
    header('HTTP/1.1 403 Forbidden');
    exit('Access Denied: Your IP ' . $visitor_ip . ' is not allowed.');

}


// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);


// Functions
function load_list($filename) {
    // Create directory if it doesn't exist
    $dir = dirname($filename);
    if (!file_exists($dir)) {
        if (!mkdir($dir, 0755, true)) {
            error_log("Failed to create directory: $dir");
            return [];
        }
    }
    
    if (!file_exists($filename)) {
        if (!touch($filename)) {
            error_log("Failed to create file: $filename");
            return [];
        }
        chmod($filename, 0666);
    }
    
    if (!is_readable($filename)) {
        error_log("File not readable: $filename");
        return [];
    }
    
    $content = file_get_contents($filename);
    if ($content === false) {
        error_log("Failed to read file: $filename");
        return [];
    }
    
    return array_filter(explode("\n", $content));
}

function save_list($filename, $items) {
    if (!is_writable($filename) && file_exists($filename)) {
        error_log("File not writable: $filename");
        return false;
    }
    return file_put_contents($filename, implode("\n", array_filter($items)));
}

function is_ip_assigned($ip, $exclude_domain = null) {
    $domain_ips = load_domain_ips();
    foreach ($domain_ips as $domain => $info) {
        if ($domain !== $exclude_domain && in_array($ip, $info['ips'])) {
            return $domain;
        }
    }
    return false;
}

function add_domain($domain, $action = 'block', $custom_ips = '') {
    // Basic domain validation
    if (empty($domain)) {
        error_log("Empty domain provided");
        return false;
    }
    
    // Determine which list to use
    $list_file = ($action === 'block') ? $GLOBALS['blocked_domains_file'] : $GLOBALS['allowed_domains_file'];
    $ip_file = ($action === 'block') ? $GLOBALS['blocked_ips_file'] : $GLOBALS['allowed_ips_file'];
    
    // Load current domains
    $domains = load_list($list_file);
    
    // Add if not already present
    if (!in_array($domain, $domains)) {
        $domains[] = $domain;
        
        // Get IPs for domain and add custom IPs
        $resolved_ips = gethostbynamel($domain) ?: [];
        $custom_ip_list = array_filter(array_map('trim', explode(',', $custom_ips)));
        
        // Validate custom IPs
        foreach ($custom_ip_list as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP)) {
                throw new Exception("Invalid custom IP provided: $ip");
            }
        }
        
        $ips = array_unique(array_merge($resolved_ips, $custom_ip_list));
        
        // Check for conflicts
        $conflicts = [];
        foreach ($ips as $ip) {
            if ($assigned_domain = is_ip_assigned($ip)) {
                $conflicts[] = "IP $ip is already assigned to domain $assigned_domain";
            }
        }
        
        if (!empty($conflicts)) {
            error_log("IP conflicts found: " . implode(", ", $conflicts));
            throw new Exception("Cannot add domain due to IP conflicts: " . implode(", ", $conflicts));
        }
        
        if (save_list($list_file, $domains)) {
            // Store the relationship
            $domain_ips = load_domain_ips();
            $domain_ips[$domain] = [
                'ips' => array_values($ips),
                'type' => $action
            ];
            
            if (!save_domain_ips($domain_ips)) {
                error_log("Failed to save domain-IP relationships");
                return false;
            }
            
            // Add IPs to the appropriate list
            foreach ($ips as $ip) {
                if (!empty($ip)) {
                    add_ip($ip_file, $ip);
                }
            }
            return true;
        }
    } else {
        error_log("Domain $domain already exists in the $action list");
    }
    return false;
}

function add_ip($filename, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        error_log("Invalid IP: $ip");
        return false;
    }
    
    // Check if IP is already assigned to a domain
    if ($assigned_domain = is_ip_assigned($ip)) {
        error_log("IP $ip is already assigned to domain $assigned_domain");
        throw new Exception("Cannot add IP: $ip is already assigned to domain $assigned_domain");
    }
    
    $ips = load_list($filename);
    if (!in_array($ip, $ips)) {
        $ips[] = $ip;
        if (save_list($filename, $ips)) {
            update_iptables();
            return true;
        }
    }
    return false;
}

function remove_domain($domain, $type = 'block') {
    // Determine which list to use
    $list_file = ($type === 'block') ? $GLOBALS['blocked_domains_file'] : $GLOBALS['allowed_domains_file'];
    
    // Remove from domains list
    $domains = load_list($list_file);
    $domains = array_diff($domains, [$domain]);
    
    // Remove domain-IP relationships
    $domain_ips = load_domain_ips();
    if (isset($domain_ips[$domain])) {
        // Remove associated IPs
        $ip_file = ($type === 'block') ? $GLOBALS['blocked_ips_file'] : $GLOBALS['allowed_ips_file'];
        foreach ($domain_ips[$domain]['ips'] as $ip) {
            remove_ip($ip_file, $ip);
        }
        // Remove domain from relationships
        unset($domain_ips[$domain]);
        save_domain_ips($domain_ips);
    }
    
    return save_list($list_file, $domains);
}

function remove_ip($filename, $ip) {
    $ips = load_list($filename);
    $ips = array_diff($ips, [$ip]);
    if (save_list($filename, $ips)) {
        update_iptables();
        return true;
    }
    return false;
}

function update_iptables() {
    $commands = [
        'sudo /sbin/iptables -F',
        'sudo /sbin/iptables -P INPUT ACCEPT',
        'sudo /sbin/iptables -P FORWARD ACCEPT',
        'sudo /sbin/iptables -P OUTPUT ACCEPT'
    ];
    
    // Add blocked IPs
    $blocked_ips = load_list($GLOBALS['blocked_ips_file']);
    foreach ($blocked_ips as $ip) {
        if (!empty($ip)) {
            $commands[] = "sudo /sbin/iptables -A INPUT -s $ip -j DROP";
        }
    }
    
    foreach ($commands as $cmd) {
        exec($cmd . " 2>&1", $output, $return_var);
        if ($return_var !== 0) {
            error_log("Error executing: $cmd");
            error_log("Output: " . implode("\n", $output));
        }
    }
}

function load_domain_ips() {
    $file = dirname($GLOBALS['blocked_domains_file']) . '/domain-ips.json';
    if (!file_exists($file)) {
        return [];
    }
    $content = file_get_contents($file);
    return $content ? json_decode($content, true) : [];
}

function save_domain_ips($domain_ips) {
    $file = dirname($GLOBALS['blocked_domains_file']) . '/domain-ips.json';
    
    // Create directory if it doesn't exist
    $dir = dirname($file);
    if (!file_exists($dir)) {
        if (!mkdir($dir, 0755, true)) {
            error_log("Failed to create directory: $dir");
            return false;
        }
    }
    
    // Check if file exists and is writable
    if (file_exists($file) && !is_writable($file)) {
        error_log("File not writable: $file");
        return false;
    }
    
    $result = file_put_contents($file, json_encode($domain_ips, JSON_PRETTY_PRINT));
    if ($result === false) {
        error_log("Failed to write to file: $file");
        return false;
    }
    return true;
}

// Handle form submissions
$error_message = '';
$success_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $ip = $_POST['ip'] ?? '';
    $domain = $_POST['domain'] ?? '';
    $custom_ips = $_POST['custom_ips'] ?? '';
    
    error_log("Received POST request - Action: $action, IP: $ip, Domain: $domain, Custom IPs: $custom_ips");
    
    try {
        switch ($action) {
            case 'block_domain':
                if (add_domain($domain, 'block', $custom_ips)) {
                    $success_message = "Domain $domain blocked successfully";
                } else {
                    $error_message = "Failed to block domain $domain";
                }
                break;
                
            case 'allow_domain':
                if (add_domain($domain, 'allow', $custom_ips)) {
                    $success_message = "Domain $domain allowed successfully";
                } else {
                    $error_message = "Failed to allow domain $domain";
                }
                break;
                
            case 'block_ip':
                if (add_ip($blocked_ips_file, $ip)) {
                    $success_message = "IP $ip blocked successfully";
                } else {
                    $error_message = "Failed to block IP $ip";
                }
                break;
                
            case 'allow_ip':
                if (add_ip($allowed_ips_file, $ip)) {
                    $success_message = "IP $ip allowed successfully";
                } else {
                    $error_message = "Failed to allow IP $ip";
                }
                break;
                
            case 'remove_block_domain':
                if (remove_domain($domain, 'block')) {
                    $success_message = "Domain $domain removed successfully";
                } else {
                    $error_message = "Failed to remove domain $domain";
                }
                break;
                
            case 'remove_allow_domain':
                if (remove_domain($domain, 'allow')) {
                    $success_message = "Domain $domain removed successfully";
                } else {
                    $error_message = "Failed to remove domain $domain";
                }
                break;
                
            case 'remove_block_ip':
                if (remove_ip($blocked_ips_file, $ip)) {
                    $success_message = "IP $ip removed successfully";
                } else {
                    $error_message = "Failed to remove IP $ip";
                }
                break;
                
            case 'remove_allow_ip':
                if (remove_ip($allowed_ips_file, $ip)) {
                    $success_message = "IP $ip removed successfully";
                } else {
                    $error_message = "Failed to remove IP $ip";
                }
                break;
        }
    } catch (Exception $e) {
        error_log("Exception: " . $e->getMessage());
        $error_message = "Error: " . $e->getMessage();
    }
}

// Load current lists
$blocked_ips = load_list($blocked_ips_file);
$allowed_ips = load_list($allowed_ips_file);
$blocked_domains = load_list($blocked_domains_file);
$allowed_domains = load_list($allowed_domains_file);
?>

<!DOCTYPE html>
<html>
<head>
    <title>IP and Domain Management System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .form-group { margin-bottom: 15px; padding: 15px; background: #f8f8f8; border-radius: 4px; }
        .error { color: red; padding: 10px; margin: 10px 0; background: #ffe6e6; border-radius: 4px; }
        .success { color: green; padding: 10px; margin: 10px 0; background: #e6ffe6; border-radius: 4px; }
        .allow { background-color: #e6ffe6; }
        .block { background-color: #ffe6e6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP and Domain Management System</h1>
        
        <?php if ($error_message): ?>
            <div class="error"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>
        
        <?php if ($success_message): ?>
            <div class="success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>
        
        <!-- Domain Management Form -->
        <div class="form-group">
            <h2>Domain Management</h2>
            <form method="POST">
                <div style="margin-bottom: 10px;">
                    <input type="text" name="domain" placeholder="Enter domain name" required style="width: 200px;">
                    <input type="text" name="custom_ips" placeholder="Additional IPs (comma-separated)" style="width: 250px;">
                </div>
                <div>
                    <select name="action">
                        <option value="block_domain">Block Domain</option>
                        <option value="allow_domain">Allow Domain</option>
                    </select>
                    <button type="submit">Submit</button>
                </div>
            </form>
            <small style="color: #666;">Example for Additional IPs: 192.168.1.1, 10.0.0.1</small>
        </div>

        <!-- IP Management Form -->
        <div class="form-group">
            <h2>IP Management</h2>
            <form method="POST">
                <input type="text" name="ip" placeholder="Enter IP address" required>
                <select name="action">
                    <option value="block_ip">Block IP</option>
                    <option value="allow_ip">Allow IP</option>
                </select>
                <button type="submit">Submit</button>
            </form>
        </div>
        
        <!-- Domain Status Table -->
        <h2>Domain Status</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain Name</th>
                    <th>Status</th>
                    <th>Associated IPs</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php 
                $domain_ips = load_domain_ips();
                foreach ($domain_ips as $domain => $info): 
                    $status = $info['type'];
                    $associated_ips = implode(", ", $info['ips']);
                    $row_class = ($status === 'block') ? 'block' : 'allow';
                ?>
                    <tr class="<?php echo $row_class; ?>">
                        <td><?php echo htmlspecialchars($domain); ?></td>
                        <td><?php echo ucfirst($status); ?></td>
                        <td><?php echo htmlspecialchars($associated_ips); ?></td>
                        <td>
                            <form method="POST">
                                <input type="hidden" name="domain" value="<?php echo htmlspecialchars($domain); ?>">
                                <input type="hidden" name="action" value="remove_<?php echo $status; ?>_domain">
                                <button type="submit">Remove</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- IP Status Table -->
        <h2>IP Status</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Associated Domain</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php 
                $all_ips = array_merge(
                    array_map(function($ip) { return ['ip' => $ip, 'type' => 'block']; }, $blocked_ips),
                    array_map(function($ip) { return ['ip' => $ip, 'type' => 'allow']; }, $allowed_ips)
                );
                
                foreach ($all_ips as $ip_info): 
                    $ip = $ip_info['ip'];
                    $status = $ip_info['type'];
                    if (!empty($ip)):
                        $associated_domain = "Direct " . ucfirst($status);
                        foreach ($domain_ips as $domain => $info) {
                            if (in_array($ip, $info['ips'])) {
                                $associated_domain = $domain;
                                break;
                            }
                        }
                        $row_class = ($status === 'block') ? 'block' : 'allow';
                ?>
                    <tr class="<?php echo $row_class; ?>">
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td><?php echo ucfirst($status); ?></td>
                        <td><?php echo htmlspecialchars($associated_domain); ?></td>
                        <td>
                            <form method="POST">
                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                <input type="hidden" name="action" value="remove_<?php echo $status; ?>_ip">
                                <button type="submit">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endif; ?>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>