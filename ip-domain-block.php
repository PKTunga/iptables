<?php
// Remove root check since we'll use sudo for iptables
// if (posix_getuid() !== 0) {
//     die("This script must be run as root");
// }

// Configuration
$allowed_ips_file = '/etc/ip-allowlist.conf';
$blocked_ips_file = '/etc/ip-blocklist.conf';

// Functions to manage IP lists
function load_ips($filename) {
    if (!file_exists($filename)) {
        return [];
    }
    return array_filter(explode("\n", file_get_contents($filename)));
}

function save_ips($filename, $ips) {
    return file_put_contents($filename, implode("\n", array_filter($ips)));
}

function add_ip($filename, $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    $ips = load_ips($filename);
    if (!in_array($ip, $ips)) {
        $ips[] = $ip;
        save_ips($filename, $ips);
        update_iptables();
        return true;
    }
    return false;
}

function remove_ip($filename, $ip) {
    $ips = load_ips($filename);
    $ips = array_diff($ips, [$ip]);
    save_ips($filename, $ips);
    update_iptables();
    return true;
}

function update_iptables() {
    // Use sudo to execute iptables commands
    $commands = [
        'sudo /sbin/iptables -F',
        'sudo /sbin/iptables -P INPUT ACCEPT',
        'sudo /sbin/iptables -P FORWARD ACCEPT',
        'sudo /sbin/iptables -P OUTPUT ACCEPT',
        'sudo /sbin/iptables -A INPUT -i lo -j ACCEPT',
        'sudo /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT'
    ];
    
    // Add allowed IPs
    $allowed_ips = load_ips($GLOBALS['allowed_ips_file']);
    foreach ($allowed_ips as $ip) {
        if (!empty($ip)) {
            $commands[] = "sudo /sbin/iptables -A INPUT -s $ip -j ACCEPT";
        }
    }
    
    // Add blocked IPs
    $blocked_ips = load_ips($GLOBALS['blocked_ips_file']);
    foreach ($blocked_ips as $ip) {
        if (!empty($ip)) {
            $commands[] = "sudo /sbin/iptables -A INPUT -s $ip -j DROP";
        }
    }
    
    // Execute commands
    foreach ($commands as $cmd) {
        exec($cmd . " 2>&1", $output, $return_var);
        if ($return_var !== 0) {
            error_log("Error executing command: $cmd");
            error_log("Output: " . implode("\n", $output));
        }
    }
}

function resolve_domain($domain) {
    // Remove http:// or https:// if present
    $domain = preg_replace('#^https?://#', '', $domain);
    
    // Try to resolve domain to IP addresses
    $ips = gethostbynamel($domain);
    if ($ips === false) {
        return false;
    }
    
    return array_unique($ips);
}

// Error handling
$error_message = '';
$success_message = '';

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $ip = $_POST['ip'] ?? '';
    $domain = $_POST['domain'] ?? '';
    
    try {
        if (!empty($ip)) {
            // Handle IP address
            switch ($action) {
                case 'allow':
                    if (add_ip($allowed_ips_file, $ip)) {
                        $success_message = "IP $ip added to allowlist";
                    } else {
                        $error_message = "Failed to add IP $ip to allowlist";
                    }
                    break;
                case 'block':
                    if (add_ip($blocked_ips_file, $ip)) {
                        $success_message = "IP $ip added to blocklist";
                    } else {
                        $error_message = "Failed to add IP $ip to blocklist";
                    }
                    break;
            }
        } elseif (!empty($domain)) {
            // Handle domain
            $resolved_ips = resolve_domain($domain);
            if ($resolved_ips === false) {
                $error_message = "Failed to resolve domain $domain";
            } else {
                $success_count = 0;
                foreach ($resolved_ips as $ip) {
                    if ($action === 'block' && add_ip($blocked_ips_file, $ip)) {
                        $success_count++;
                    } elseif ($action === 'allow' && add_ip($allowed_ips_file, $ip)) {
                        $success_count++;
                    }
                }
                if ($success_count > 0) {
                    $success_message = "Domain $domain processed. Added $success_count IP(s)";
                } else {
                    $error_message = "No new IPs added for domain $domain";
                }
            }
        }
        // ... rest of the switch cases for remove actions
    } catch (Exception $e) {
        $error_message = "Error: " . $e->getMessage();
    }
}

// Load current IPs
$allowed_ips = load_ips($allowed_ips_file);
$blocked_ips = load_ips($blocked_ips_file);
?>

<!DOCTYPE html>
<html>
<head>
    <title>IP Management System</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        .form-group {
            margin-bottom: 15px;
            padding: 15px;
            background: #f8f8f8;
            border-radius: 4px;
        }
        .error {
            color: red;
            padding: 10px;
            margin: 10px 0;
            background: #ffe6e6;
            border-radius: 4px;
        }
        .success {
            color: green;
            padding: 10px;
            margin: 10px 0;
            background: #e6ffe6;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP Management System</h1>
        
        <?php if ($error_message): ?>
            <div class="error"><?php echo htmlspecialchars($error_message); ?></div>
        <?php endif; ?>
        
        <?php if ($success_message): ?>
            <div class="success"><?php echo htmlspecialchars($success_message); ?></div>
        <?php endif; ?>
        
        <!-- Add IP Form -->
        <div class="form-group">
            <h2>Add IP or Domain</h2>
            <form method="POST">
                <div style="margin-bottom: 10px;">
                    <input type="text" name="ip" placeholder="Enter IP address (e.g., 1.2.3.4)" style="margin-right: 10px;">
                    <span>OR</span>
                    <input type="text" name="domain" placeholder="Enter domain (e.g., example.com)" style="margin-left: 10px;">
                </div>
                <div>
                    <select name="action">
                        <option value="allow">Allow</option>
                        <option value="block">Block</option>
                    </select>
                    <button type="submit">Add</button>
                </div>
            </form>
        </div>
        
        <!-- Allowed IPs Table -->
        <h2>Allowed IPs</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($allowed_ips as $ip): ?>
                    <?php if (!empty($ip)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                <input type="hidden" name="action" value="remove_allowed">
                                <button type="submit">Remove</button>
                            </form>
                        </td>
                    </tr>
                    <?php endif; ?>
                <?php endforeach; ?>
            </tbody>
        </table>
        
        <!-- Blocked IPs Table -->
        <h2>Blocked IPs</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($blocked_ips as $ip): ?>
                    <?php if (!empty($ip)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                <input type="hidden" name="action" value="remove_blocked">
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
