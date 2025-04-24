#!/bin/bash

# Enhanced LEMP Server Setup Script with Single Domain, SSL, Mail Server, Roundcube, SFTP, PHP Version Selection, and Email Creation
# Tested on Ubuntu 20.04/22.04
# Run as root: sudo bash setup_lemp_enhanced.sh

# Exit on error
set -e

# Check if script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
fi

# Log file for setup
LOG_FILE="/var/log/lemp_setup_$(date +%F_%H-%M-%S).log"
exec 1> >(tee -a "$LOG_FILE")
exec 2>&1

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to validate domain
validate_domain() {
    local domain=$1
    if [[ -z "$domain" || ! "$domain" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "Invalid domain name: $domain"
        exit 1
    fi
}

# Function to validate email
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "Invalid email format: $email"
        exit 1
    fi
}

# Function to select PHP version
select_php_version() {
    log "Available PHP versions:"
    php_versions=($(apt-cache search php | grep '^php[0-9]\.[0-9]-fpm' | awk '{print $1}' | sed 's/php\([0-9]\.[0-9]\)-fpm/\1/' | sort -u))
    if [[ ${#php_versions[@]} -eq 0 ]]; then
        log "No PHP versions found. Installing default PHP."
        apt install -y php-fpm
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
        return
    fi

    for i in "${!php_versions[@]}"; do
        echo "$((i+1))) ${php_versions[i]}"
    done
    read -p "Select a PHP version number: " PHP_INDEX

    if [[ ! "$PHP_INDEX" =~ ^[0-9]+$ || $PHP_INDEX -lt 1 || $PHP_INDEX -gt ${#php_versions[@]} ]]; then
        log "Invalid selection. Using default PHP version."
        apt install -y php-fpm
        PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
        return
    fi

    PHP_VERSION=${php_versions[$((PHP_INDEX-1))]}
    apt install -y php${PHP_VERSION}-fpm php${PHP_VERSION}-mysql php${PHP_VERSION}-cli php${PHP_VERSION}-curl php${PHP_VERSION}-gd php${PHP_VERSION}-mbstring php${PHP_VERSION}-xml php${PHP_VERSION}-zip php${PHP_VERSION}-imap php${PHP_VERSION}-intl
    log "PHP $PHP_VERSION installed."
}

# Function to backup configurations
backup_configs() {
    local domain=$1
    local backup_dir="/root/backups/lemp_$(date +%F_%H-%M-%S)"
    mkdir -p "$backup_dir"
    cp -r /etc/nginx "$backup_dir/nginx"
    cp -r /etc/postfix "$backup_dir/postfix"
    cp -r /etc/dovecot "$backup_dir/dovecot"
    cp -r /etc/opendkim "$backup_dir/opendkim"
    cp -r /var/www/$domain "$backup_dir/www_$domain"
    log "Backed up configurations to $backup_dir"
}

# Function to configure firewall
configure_firewall() {
    log "Configuring UFW firewall..."
    apt install -y ufw
    ufw allow 22/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 25/tcp
    ufw allow 110/tcp
    ufw allow 143/tcp
    ufw allow 465/tcp
    ufw allow 587/tcp
    ufw allow 993/tcp
    ufw allow 995/tcp
    ufw --force enable
    log "Firewall configured."
}

# Function to secure MySQL
secure_mysql() {
    log "Securing MySQL installation..."
    apt install -y expect
    MYSQL_ROOT_PASS=$(openssl rand -base64 12)
    expect <<EOF
spawn mysql_secure_installation
expect "Enter current password for root (enter for none):"
send "\r"
expect "Set root password?"
send "y\r"
expect "New password:"
send "$MYSQL_ROOT_PASS\r"
expect "Re-enter new password:"
send "$MYSQL_ROOT_PASS\r"
expect "Remove anonymous users?"
send "y\r"
expect "Disallow root login remotely?"
send "y\r"
expect "Remove test database and access to it?"
send "y\r"
expect "Reload privilege tables now?"
send "y\r"
expect eof
EOF
    log "MySQL secured. Root password: $MYSQL_ROOT_PASS"
}

# Function to configure log rotation
configure_log_rotation() {
    local domain=$1
    log "Configuring log rotation..."
    cat > /etc/logrotate.d/lemp_$domain <<EOF
/var/www/$domain/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 www-data www-data
}
/var/log/postfix/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
/var/log/dovecot/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
    log "Log rotation configured."
}

# Function to install Certbot and obtain SSL certificate
install_ssl() {
    local domain=$1
    log "Installing SSL certificate for $domain..."
    apt install -y certbot python3-certbot-nginx
    certbot --nginx --non-interactive --agree-tos --email admin@$domain -d $domain -d www.$domain -d webmail.$domain || {
        log "SSL certificate installation failed for $domain. Continuing without SSL."
    }
}

# Function to configure mail server
configure_mail() {
    local domain=$1
    local hostname=$(hostname -f)
    log "Configuring mail server for $domain..."

    apt install -y postfix postfix-mysql dovecot-core dovecot-imapd dovecot-pop3d opendkim opendkim-tools
    mkdir -p /etc/opendkim/keys/$domain
    opendkim-genkey -s mail -d $domain -D /etc/opendkim/keys/$domain
    chown opendkim:opendkim /etc/opendkim/keys/$domain/mail.private
    chmod 600 /etc/opendkim/keys/$domain/mail.private

    cat >> /etc/opendkim.conf <<EOF
Domain                  $domain
KeyFile                 /etc/opendkim/keys/$domain/mail.private
Selector                mail
EOF

    echo "mail._domainkey.$domain $domain:mail:/etc/opendkim/keys/$domain/mail.private" >> /etc/opendkim/KeyTable
    echo "*@$domain mail._domainkey.$domain" >> /etc/opendkim/SigningTable

    postconf -e "virtual_mailbox_domains = $domain"
    postconf -e "virtual_mailbox_base = /var/mail/vhosts"
    postconf -e "virtual_mailbox_maps = hash:/etc/postfix/vmailbox"
    postconf -e "virtual_uid_maps = static:5000"
    postconf -e "virtual_gid_maps = static:5000"

    mkdir -p /var/mail/vhosts/$domain
    echo "admin@$domain $domain/admin/" >> /etc/postfix/vmailbox
    postmap /etc/postfix/vmailbox

    cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
mail_location = maildir:/var/mail/vhosts/%d/%n
EOF

    systemctl restart postfix dovecot opendkim || log "Failed to restart mail services"
    local dkim_record=$(cat /etc/opendkim/keys/$domain/mail.txt | grep -o 'v=DKIM1;.*' | tr -d '\t\n' | sed 's/ //g' | sed 's/("\|")//g')
    log "DNS Records for $domain:"
    log "Type: TXT, Host: @, Value: v=spf1 a mx ~all"
    log "Type: TXT, Host: mail._domainkey, Value: $dkim_record"
    log "Type: TXT, Host: _dmarc, Value: v=DMARC1; p=none; rua=mailto:dmarc-reports@$domain;"
}

# Function to configure Roundcube
configure_roundcube() {
    local domain=$1
    local db_name=$(echo $domain | tr . _)_db
    local db_user=$(echo $domain | tr . _)_user
    local db_pass=$(openssl rand -base64 12)
    log "Configuring Roundcube for $domain..."

    apt install -y roundcube roundcube-mysql
    mkdir -p /var/www/$domain/webmail
    cp -r /usr/share/roundcube/* /var/www/$domain/webmail/
    chown -R www-data:www-data /var/www/$domain/webmail
    chmod -R 755 /var/www/$domain/webmail

    mysql -e "CREATE DATABASE roundcube_$db_name;"
    mysql -e "CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass';"
    mysql -e "GRANT ALL PRIVILEGES ON roundcube_$db_name.* TO '$db_user'@'localhost';"
    mysql -u $db_user -p$db_pass roundcube_$db_name < /var/www/$domain/webmail/SQL/mysql.initial.sql

    cat > /var/www/$domain/webmail/config/config.inc.php <<EOF
<?php
\$config = [];
\$config['db_dsnw'] = 'mysql://$db_user:$db_pass@localhost/roundcube_$db_name';
\$config['default_host'] = 'localhost';
\$config['smtp_server'] = 'localhost';
\$config['smtp_port'] = 25;
\$config['smtp_user'] = '%u';
\$config['smtp_pass'] = '%p';
\$config['support_url'] = '';
\$config['product_name'] = 'Roundcube Webmail';
\$config['des_key'] = '$(openssl rand -base64 18)';
\$config['plugins'] = ['archive', 'zipdownload'];
\$config['language'] = 'en_US';
\$config['enable_spellcheck'] = true;
?>
EOF

    cat > /etc/nginx/sites-available/$domain-webmail <<EOF
server {
    listen 80;
    listen 443 ssl;
    server_name webmail.$domain;
    root /var/www/$domain/webmail;
    index index.php index.html;

    access_log /var/www/$domain/logs/webmail_access.log;
    error_log /var/www/$domain/logs/webmail_error.log;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    location / {
        try_files \$uri \$uri/ /index.php;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~* ^/(config|temp|logs)/ {
        deny all;
    }
}
EOF

    ln -s /etc/nginx/sites-available/$domain-webmail /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx || log "Failed to reload Nginx"
}

# Function to configure SFTP
configure_sftp() {
    log "Available domains:"
    domains=($(ls /var/www | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'))
    if [[ ${#domains[@]} -eq 0 ]]; then
        log "No domains found in /var/www"
        exit 1
    fi

    for i in "${!domains[@]}"; do
        echo "$((i+1))) ${domains[i]}"
    done
    read -p "Select a domain number for SFTP setup: " DOMAIN_INDEX

    if [[ ! "$DOMAIN_INDEX" =~ ^[0-9]+$ || $DOMAIN_INDEX -lt 1 || $DOMAIN_INDEX -gt ${#domains[@]} ]]; then
        log "Invalid selection"
        exit 1
    fi

    local domain=${domains[$((DOMAIN_INDEX-1))]}
    log "Configuring SFTP for $domain..."

    local sftp_user=$(echo $domain | tr . _)_sftp
    local sftp_pass=$(openssl rand -base64 12)
    useradd -m -d /var/www/$domain -s /bin/false $sftp_user
    echo "$sftp_user:$sftp_pass" | chpasswd

    chown $sftp_user:www-data /var/www/$domain/public_html
    chmod 750 /var/www/$domain/public_html
    chown root:root /var/www/$domain
    chmod 755 /var/www/$domain

    if ! grep -q "Match User $sftp_user" /etc/ssh/sshd_config; then
        cat >> /etc/ssh/sshd_config <<EOF
Match User $sftp_user
    ChrootDirectory /var/www/$domain
    ForceCommand internal-sftp
    AllowTcpForwarding no
    X11Forwarding no
EOF
    fi

    systemctl restart sshd || log "Failed to restart SSHD"
    log "SFTP configured for $domain!"
    log "SFTP Details:"
    log "  SFTP User: $sftp_user"
    log "  SFTP Password: $sftp_pass"
    log "  SFTP Host: $(hostname -I | awk '{print $1}')"
    log "  SFTP Port: 22"
}

# Function to create email account
create_email() {
    log "Available domains:"
    domains=($(ls /var/www | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'))
    if [[ ${#domains[@]} -eq 0 ]]; then
        log "No domains found in /var/www"
        exit 1
    fi

    for i in "${!domains[@]}"; do
        echo "$((i+1))) ${domains[i]}"
    done
    read -p "Select a domain number for email creation: " DOMAIN_INDEX

    if [[ ! "$DOMAIN_INDEX" =~ ^[0-9]+$ || $DOMAIN_INDEX -lt 1 || $DOMAIN_INDEX -gt ${#domains[@]} ]]; then
        log "Invalid selection"
        exit 1
    fi

    local domain=${domains[$((DOMAIN_INDEX-1))]}
    log "Creating email for $domain..."
    read -p "Enter email username (e.g., user for user@$domain): " EMAIL_USER
    local email_pass=$(openssl rand -base64 12)

    echo "$EMAIL_USER@$domain $domain/$EMAIL_USER/" >> /etc/postfix/vmailbox
    postmap /etc/postfix/vmailbox
    mkdir -p /var/mail/vhosts/$domain/$EMAIL_USER
    chown -R 5000:5000 /var/mail/vhosts/$domain/$EMAIL_USER
    chmod -R 700 /var/mail/vhosts/$domain/$EMAIL_USER

    systemctl restart postfix || log "Failed to restart Postfix"
    log "Email account created for $domain!"
    log "Email Details:"
    log "  Email Address: $EMAIL_USER@$domain"
    log "  Email Password: $email_pass"
    log "  Webmail Access: https://webmail.$domain"
    log "  IMAP/POP3 Server: $domain"
    log "  SMTP Server: $domain"
}

# Function to add domain
add_domain() {
    local domain=$1
    validate_domain "$domain"
    local php_version=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || echo "")
    if [[ -z "$php_version" ]]; then
        log "PHP-FPM not found. Selecting PHP version..."
        select_php_version
    else
        log "Current PHP version: $php_version"
        read -p "Do you want to change the PHP version? (y/n): " CHANGE_PHP
        if [[ "$CHANGE_PHP" == "y" || "$CHANGE_PHP" == "Y" ]]; then
            select_php_version
        fi
    fi

    log "Adding domain: $domain..."
    mkdir -p /var/www/$domain/{public_html,logs}
    chown -R www-data:www-data /var/www/$domain
    chmod -R 755 /var/www/$domain

    cat > /var/www/$domain/public_html/index.php <<EOF
<?php
phpinfo();
?>
EOF

    cat > /etc/nginx/sites-available/$domain <<EOF
server {
    listen 80;
    server_name $domain www.$domain;
    root /var/www/$domain/public_html;
    index index.php index.html index.htm;

    access_log /var/www/$domain/logs/access.log;
    error_log /var/www/$domain/logs/error.log;

    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Frame-Options "SAMEORIGIN";
    add_header Referrer-Policy "strict-origin-when-cross-origin";

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff2?|ttf|svg|eot|otf|ttc|ttf|woff)$ {
        expires max;
        log_not_found off;
    }
}
EOF

    ln -s /etc/nginx/sites-available/$domain /etc/nginx/sites-enabled/
    nginx -t && systemctl reload nginx || log "Failed to reload Nginx"
    backup_configs "$domain"
}

# Main setup function
main() {
    log "Starting LEMP server setup..."
    apt update && apt upgrade -y
    apt install -y nginx mariadb-server unzip curl expect
    secure_mysql
    configure_firewall

    read -p "Enter domain name (e.g., example.com): " DOMAIN
    validate_domain "$DOMAIN"
    add_domain "$DOMAIN"
    install_ssl "$DOMAIN"
    configure_mail "$DOMAIN"
    configure_roundcube "$DOMAIN"
    configure_log_rotation "$DOMAIN"
    configure_sftp
    create_email

    log "LEMP server setup completed successfully!"
    log "Setup details logged to $LOG_FILE"
}

main