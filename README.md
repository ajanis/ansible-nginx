# Ansible-Nginx

<!-- MarkdownTOC -->

- Requirements
- Role Variables
  - defaults/main.yml
  - vars/Debian.yml
  - vars/RedHat.yml
- Dependencies
- Example Group Variables
- Example Playbook
- License
- Author Information

<!-- /MarkdownTOC -->

Set up an NGINX webserver with configurable vhosts, reverse proxies, proxy caching, ssl and Fail2Ban

## Requirements

If you wish to enable SSL, you will need to update the variables for ```ssl_cert``` and ```ssl_key```

To use the custom PFSense URLTable Ban Action for Fail2Ban, you will need to configure an SSH user on your PFSense server with an SSH Key and update the following variables. *** NOTE: This configuration is beyond the scope of this document ***

```
# Custom PFSense URLTable Ban Action
#fail2ban_banaction: urltable

# Set these variables if using URLTable Ban Action
fail2ban_pfsense_ip:
fail2ban_pfsense_user:
fail2ban_urltable_file:
fail2ban_ssh_private_key:
```



## Role Variables

### defaults/main.yml

```
nginx_user: www-data
nginx_group: www-data

ssl_key:
ssl_cert:

nginx_index:
  - 'index.php'
  - 'index.html'
  - 'index.htm'
nginx_server_tokens: "off"
nginx_sendfile: "on"
nginx_tcp_nopush: "on"
nginx_default_type: "application/octet-stream"

nginx_gzip: "on"
nginx_gzip_vary: "on"
nginx_gzip_disable: "MSIE [1-6]."
nginx_gzip_proxied: any
nginx_gzip_http_version: "1.0"
nginx_gzip_min_length: "1000"
nginx_gzip_comp_level: "6"
nginx_gzip_buffers: "32 8k"

nginx_log_format_main: |
  '$remote_addr - $remote_user [$time_local]'
  '"$request" $status $body_bytes_sent'
  '"$http_referer" "$http_user_agent"'
  '$request_time $upstream_connect_time $http_x_forwarded_for $upstream_cache_status';

nginx_access_log: "/var/log/nginx/access.log  main"

nginx_worker_processes: "32"
nginx_worker_connections: "1024"
nginx_worker_rlimit_nofile: "409600"
nginx_server_names_hash_bucket_size: "1024"
nginx_upstream_repo: true
nginx_upstream_repo_baseurl: "http://nginx.org/packages"
nginx_upstream_repo_key: "http://nginx.org/keys/nginx_signing.key"

nginx_proxy_temp_path: "/tmp/nginx-proxy-temp"
nginx_proxy_buffering: "on"
nginx_proxy_connect_timeout: "180s"
nginx_proxy_send_timeout: "180s"
nginx_proxy_read_timeout: "180s"
nginx_proxy_buffers: "32 32k"
nginx_proxy_buffer_size: "512k"
nginx_proxy_busy_buffers_size: "512k"
nginx_proxy_max_temp_file_size: "2048m"
nginx_proxy_temp_file_write_size: "1m"
nginx_client_body_buffer_size: "1m"
nginx_client_body_temp_path: "/tmp/nginx-client-body-temp"
nginx_client_body_timeout: "180s"
nginx_client_max_body_size: "0"
nginx_client_header_buffer_size: "4k"
nginx_client_header_timeout: "180s"

nginx_proxy_cache_enabled: True
nginx_proxy_cache: "nginx-cache"
nginx_proxy_cache_path: "/tmp/{{ nginx_proxy_cache }}"
nginx_proxy_cache_key: '$scheme$host$proxy_host$request_uri'
nginx_proxy_cache_size: "16m"
nginx_proxy_cache_max_size: "2048m"
nginx_proxy_cache_inactive: "1M"
nginx_proxy_cache_use_temp_path: "off"
nginx_proxy_cache_valid: 
  - "200 302 1M"
  - "404 1m"
nginx_proxy_cache_min_uses: "1"
nginx_proxy_cache_background_update: "on"
nginx_proxy_cache_use_stale:
  - error
  - timeout
  - updating
  - http_500
  - http_502
  - http_503
  - http_504
nginx_proxy_cache_revalidate: "on"
nginx_proxy_cache_lock: "on"

nginx_fastcgi_read_timeout: "180s"
nginx_fastcgi_send_timeout: "180s"
nginx_default_servername: "{{ ansible_fqdn }}"
nginx_default_docroot: "/var/lib/www"
nginx_http_listen: 80
nginx_https_listen: 443

nginx_keepalive: 32
nginx_keepalive_requests: 100
nginx_keepalive_timeout: "300s"

nginx_vhosts:
  - servername: "home.example.com"
    serveralias: "example.com www.example.com {{ ansible_eth0.ipv4.address }}"
    serverlisten: "80 default_server"
    locations:
      - name: /
        docroot: "/var/lib/www"
        extra_parameters: |
          fancyindex on;

nginx_vhosts_ssl:
  - servername: "home.example.com"
    serveralias: "example.com www.example.com"
    serverlisten: "443 default_server"
    ssl_certchain: "{{ ssl_cert }}"
    ssl_privkey: "{{ ssl_key }}"
    ssl_certpath: "/etc/ssl/certs/custom.pem"
    ssl_keypath: "{/etc/ssl/private/custom.key"
    locations:
      - name: /
        docroot: "/var/lib/www"
        extra_parameters: |
          fancyindex on;

fail2ban_enable: False

fail2ban_loglevel: INFO
fail2ban_logtarget: SYSLOG
fail2ban_syslog_target: /var/log/fail2ban.log
fail2ban_syslog_facility: 1
fail2ban_socket: /var/run/fail2ban/fail2ban.sock
fail2ban_pidfile: /var/run/fail2ban/fail2ban.pid
fail2ban_sendername: 'Fail2ban'
fail2ban_ignoreips:
 - 127.0.0.1/8
 - 10.0.0.0/8
 - 192.168.0.0/8
fail2ban_bantime: 1h
fail2ban_maxretry: 3
fail2ban_findtime: 5m
fail2ban_backend: auto
fail2ban_usedns: "warn"
fail2ban_destemail: root@localhost

fail2ban_banaction: iptables-multiport

# Custom PFSense URLTable Ban Action
#fail2ban_banaction: urltable

# Set these variables if using URLTable Ban Action
fail2ban_pfsense_ip:
fail2ban_pfsense_user:
fail2ban_urltable_file:
fail2ban_ssh_private_key:


fail2ban_mta: sendmail
fail2ban_protocol: tcp
fail2ban_chain: '<known/chain>'
fail2ban_action: '%(action_)s'
fail2ban_services:
  - name: nginx-http-auth
    enabled: True
    filter: nginx-http-auth
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-noscript
    enabled: True
    filter: nginx-noscript
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-badbots
    enabled: True
    filter: nginx-badbots
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-botsearch
    enabled: True
    filter: nginx-botsearch
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-nohome
    enabled: True
    filter: nginx-nohome
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-404
    enabled: True
    filter: nginx-404
    port: http,https
    logpath: /var/log/nginx/*.log
```

### vars/Debian.yml
```
nginx_pkgs:
  - nginx-common
  - nginx-extras
  - libnginx-mod-http-fancyindex

nginx_cfg_dir: /etc/nginx/conf.d
nginx_default_site:
  - /etc/nginx/sites-enabled/default
  - /etc/nginx/sites-available/default
  - /etc/nginx/conf.d/default.conf
  - /etc/nginx/conf.d/example_ssl.conf
```

### vars/RedHat.yml
```
nginx_pkgs: 
  - nginx-common
  - nginx-extras
  - libnginx-mod-http-fancyindex

nginx_cfg_dir: /etc/nginx/conf.d
nginx_default_site:
  - /etc/nginx/conf.d/default.conf
```

## Dependencies
N/A

## Example Group Variables

```
www_domain: 'home.example.com'

ssl_key: "{{ vault_ssl_key }}"
ssl_cert: "{{ vault_ssl_cert }}"

nginx_user: "media"
nginx_group: "media"
nginx_default_servername: "{{ www_domain }} www.example.com example.com"
nginx_default_docroot: "/var/lib/www"

fail2ban_enable: True

fail2ban_bantime: "-1" #Permanent ban
fail2ban_findtime: "10m"
fail2ban_maxretry: "2"
fail2ban_usedns: "raw"
fail2ban_logtarget: /var/log/fail2ban.log

# Custom PFSense URLTable Ban Action

fail2ban_banaction: urltable
fail2ban_pfsense_ip: "10.0.10.1"
fail2ban_pfsense_user: fail2ban
fail2ban_urltable_file: "{{ data_mount_root }}/{{ www_directory }}/fail2ban.txt"
fail2ban_ssh_private_key: "{{ vault_fail2ban_ssh_private_key }}"


fail2ban_services:
  - name: nginx-http-auth
    enabled: True
    filter: nginx-http-auth
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-noscript
    enabled: True
    filter: nginx-noscript
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-badbots
    enabled: True
    filter: nginx-badbots
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-botsearch
    enabled: True
    filter: nginx-botsearch
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-nohome
    enabled: True
    filter: nginx-nohome
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-404
    enabled: True
    filter: nginx-404
    port: http,https
    logpath: /var/log/nginx/*.log
  - name: nginx-401
    enabled: True
    filter: nginx-401
    port: http,https
    findtime: '1m'
    bantime: '5m'
    maxretry: 3
    logpath:
      - /var/log/nginx/plex*.log

nginx_backends:

  - service: plex
    servers:
      - 0.0.0.0:32400

nginx_vhosts:
  - servername: "home.example.com"
    serveralias: "example.com www.example.com {{ ansible_eth0.ipv4.address }}"
    serverlisten: "80 default_server"
    locations:
      - name: /
        docroot: "/var/lib/www"
        extra_parameters: |
          fancyindex on;
          fancyindex_localtime on; #on for local time zone. off for GMT
          fancyindex_exact_size off; #off for human-readable. on for exact size in bytes
          fancyindex_header "/fancyindex/header.html";
          fancyindex_footer "/fancyindex/footer.html";
          fancyindex_ignore "fancyindex"; #ignore this directory when showing list
          fancyindex_ignore "iot_firewall_allow.txt";
          fancyindex_ignore "fail2ban.txt";
          fancyindex_ignore "robots.txt";

  - servername: plex.home.example.com
    serveralias: plex
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: plex
        custom_css: plex/dark.css
      - name: >
          '~* (^/(photo|media|image|images|mediacover|pms_image_proxy)|\.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|css|js)$)'
        proxy: True
        proxy_cache: True
        backend: plex


nginx_vhosts_ssl:
  - servername: "home.example.com"
    serveralias: "example.com www.example.com"
    serverlisten: "443 default_server"
    ssl_certchain: "{{ ssl_cert }}"
    ssl_privkey: "{{ ssl_key }}"
    ssl_certpath: "/etc/ssl/certs/custom.pem"
    ssl_keypath: "{/etc/ssl/private/custom.key"
    locations:
      - name: /
        docroot: "/var/lib/www"
        extra_parameters: |
          fancyindex on;
          fancyindex_localtime on; #on for local time zone. off for GMT
          fancyindex_exact_size off; #off for human-readable. on for exact size in bytes
          fancyindex_header "/fancyindex/header.html";
          fancyindex_footer "/fancyindex/footer.html";
          fancyindex_ignore "fancyindex"; #ignore this directory when showing list
          fancyindex_ignore "iot_firewall_allow.txt";
          fancyindex_ignore "fail2ban.txt";
          fancyindex_ignore "robots.txt";


  - servername: plex.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_cert }}"
    ssl_privkey: "{{ ssl_key }}"
    ssl_certpath: "/etc/ssl/certs/custom.pem"
    ssl_keypath: "{/etc/ssl/private/custom.key"
    locations:
      - name: /
        proxy: True
        backend: plex
        custom_css: plex/dark.css
      - name: >
          '~* (^/(photo|media|image|images|mediacover|pms_image_proxy)|\.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|css|js)$)'
        proxy: True
        proxy_cache: True
        backend: plex



```


## Example Playbook

```
- name: "[NGINX] :: Deploy NGINX Webserver / reverse proxy"
  hosts:
    - all
  become: True
  tasks:
    - include_role:
        name: nginx

```

## License

MIT

## Author Information

Created by Alan Janis
