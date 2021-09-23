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

```yaml
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

```yaml
---
slurp_ssl_keys_from_remote: False
ssl_slurp_remote_host:
ssl_cert_slurp_path:
ssl_key_slurp_path:
ssl_cert:
ssl_key:


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
  '$remote_addr - $remote_user [$time_local] '
  '$host "$request" $status $body_bytes_sent '
  '"$http_referer" "$http_user_agent" '
  '$request_time $upstream_connect_time $http_x_forwarded_for $upstream_cache_status';

nginx_access_log: "/var/log/nginx/access.log  main"


nginx_enable_rtmp: False
nginx_rtmp_listen_port: 1935
nginx_rtsp_transport_proto: tcp
nginx_rtsp_camera_feed: 'rtsp://camera_ip:7447/stream1'
nginx_hls_camera_feed_transcode_dir: /tmp/hls
nginx_hls_camera_transcode_index: "index.{{ nginx_hls_segment_list_type }}"
nginx_hls_camera_transcode_path: "{{ nginx_hls_camera_feed_transcode_dir }}/{{ nginx_hls_camera_transcode_index }}"
nginx_hls_segment_list_type: m3u8
nginx_hls_segment_format: mpegts
nginx_hls_segment_list_entry_prefix: /
nginx_fflags: |
  nobuffer -rtsp_transport tcp -i {{ nginx_rtsp_camera_feed }} \
  -vsync 0 -copyts -vcodec copy \
  -movflags frag_keyframe+empty_moov -an \
  -hls_flags delete_segments+append_list \
  -f segment -segment_list_flags live \
  -segment_time 1 -segment_list_size 3 -segment_format {{ nginx_hls_segment_format }} \
  -segment_list {{ nginx_hls_camera_transcode_path }} \
  -segment_list_type {{ nginx_hls_segment_list_type }} \
  -segment_list_entry_prefix {{ nginx_hls_segment_list_entry_prefix }} \
  {{ nginx_hls_camera_feed_transcode_dir }}/%d.ts > /var/log/ffmpeg 2>&1

nginx_rtmp_ffmpeg_command: "{{ nginx_ffmpeg_path }} -fflags {{ nginx_fflags }}"

nginx_module_pkgs: []

nginx_modules_enabled: []

nginx_worker_processes: "32"
nginx_worker_connections: "1024"
nginx_worker_rlimit_nofile: "409600"
nginx_server_names_hash_bucket_size: "1024"

nginx_extra_parameters:
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
nginx_default_docroot: "/usr/share/nginx/html"
nginx_http_listen: 80
nginx_https_listen: 443

nginx_keepalive: 32
nginx_keepalive_requests: 100
nginx_keepalive_timeout: "300s"


nginx_vhosts:
  - servername: localhost;
    serverlisten: 80;
    locations:
      - name: /nginx_status
        extra_parameters: |
          stub_status;
          access_log off;
          allow 127.0.0.1;
          deny all;
  - servername: "home.example.com"
    serveralias: "example.com www.home.example.com {{ ansible_eth0.ipv4.address }}"
    serverlisten: "80 default_server"
    locations:
      - name: /
        docroot: "{{ data_mount_root }}/{{ www_directory }}"

nginx_vhosts_ssl: []
#  - servername: "home.example.com"
#    serveralias: "example.com www.example.com www.home.example.com"
#    serverlisten: "443 default_server"
#    ssl_certchain: "{{ ssl_certchain }}"
#    ssl_privkey: "{{ ssl_privkey }}"
#    ssl_certpath: "{{ ssl_certpath }}"
#    ssl_keypath: "{{ ssl_keypath }}"
#    locations:
#      - name: /
#        docroot: "{{ data_mount_root }}/{{ www_directory }}"

# The following Grok patterns can be used to parse the above-defined nginx 'main' access log format and the default fail2ban.log file

nginx_accesslog_grokpattern: '%{CLIENT:client_ip} - %{NOTSPACE:ident} \[%{HTTPDATE:ts:ts-httpd}\] %{NOTSPACE:request_host:tag} "(?:%{WORD:verb:tag} %{NOTSPACE:request} (?:HTTP/%{NUMBER:http_version:float})?|%{DATA})" %{NUMBER:resp_code:tag} (?:%{NUMBER:resp_bytes:int}|-) "%{NOTSPACE:referrer}" "%{DATA:agent:tag}" (?:%{NUMBER:request_time}|-) (?:%{NUMBER:upstream_connect_time}|-) %{NOTSPACE:x_forwarded_for} %{NOTSPACE:upstream_cache_status:tag}'
fail2ban_banlog_grokpattern: '%{TIMESTAMP_ISO8601:timestamp} %{WORD:log_src}.%{WORD:src_action} *\[%{INT:fail2ban_digit}\]: %{WORD:loglevel:tag} *\[%{NOTSPACE:service:tag}\] %{GREEDYDATA:ban_status:tag} %{IP:clientip:tag}'

# Example with Telegraf 'logparser' input configuration
#
#- name: logparser
#  options:
#    files:
#      - "/var/log/nginx/*.log"
#    from_beginning: "false"
#    grok:
#      patterns:
#        - '{{ nginx_accesslog_grokpattern }}'
#      measurement: nginx_access_log
#- name: logparser
#  options:
#    files:
#      - "/var/log/fail2ban.log"
#    from_beginning: "false"
#    grok:
#      patterns:
#        - '{{ fail2ban_banlog_grokpattern }}'
#      measurement: fail2ban_log

fail2ban_enable: False

fail2ban_loglevel: INFO
fail2ban_logtarget: SYSLOG
fail2ban_syslog_target: /var/log/fail2ban.log
fail2ban_syslog_facility: 1
fail2ban_socket: /var/run/fail2ban/fail2ban.sock
fail2ban_pidfile: /var/run/fail2ban/fail2ban.pid
fail2ban_sendername: 'Fail2ban'
fail2ban_ignoreips:
  - <network_address>/<cidr_prefix>
  - <network_address>/<cidr_prefix>
  - <network_address>/<cidr_prefix>
fail2ban_bantime: 1h
fail2ban_maxretry: 3
fail2ban_findtime: 5m
fail2ban_backend: auto
fail2ban_usedns: "warn"
fail2ban_destemail: root@localhost

fail2ban_banaction: iptables-multiport
#fail2ban_banaction: pfsense
#fail2ban_banaction: urltable

# Custom PFSense pfSSH Ban Action

# Set these variables if using pfsense Ban Action
#fail2ban_pfsense_ip:
#fail2ban_pfsense_user:
#fail2ban_ssh_private_key:

# Custom PFSense URLTable Ban Action
#fail2ban_banaction: urltable

# Set these variables if using URLTable Ban Action
#fail2ban_pfsense_ip:
#fail2ban_pfsense_user:
#fail2ban_ssh_private_key:
#fail2ban_urltable_file:



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


nginx_allowed_ports:
  - "80/tcp"
  - "443/tcp"
```

### vars/Debian.yml
```yaml
---
nginx_upstream_repo: True
nginx_upstream_repo_baseurl: "http://nginx.org/packages"
nginx_upstream_repo_key: "http://nginx.org/keys/nginx_signing.key"

nginx_ppa_reqs:
  - software-properties-common

nginx_ppa_repo: "ppa:nginx/stable"

nginx_pkgs:
  - nginx-common
  - nginx-extras

nginx_cfg_dir: /etc/nginx/conf.d
nginx_default_site:
  - /etc/nginx/sites-enabled/default
  - /etc/nginx/sites-available/default
  - /etc/nginx/conf.d/default.conf
  - /etc/nginx/conf.d/example_ssl.conf

nginx_default_user: www-data
nginx_default_group: www-data

nginx_ffmpeg_path: /usr/bin/ffmpeg

```

### vars/RedHat.yml
```yaml
---
#nginx_upstream_repo: true
#nginx_upstream_repo_baseurl: "http://nginx.org/packages"
#nginx_upstream_repo_key: "http://nginx.org/keys/nginx_signing.key"

nginx_pkgs:
  - nginx
#  - libnginx-mod-http-fancyindex
#  - php-fpm

nginx_cfg_dir: /etc/nginx/conf.d
nginx_default_site:
  - /etc/nginx/conf.d/default.conf

nginx_default_user: nginx
nginx_default_group: nginx

nginx_ffmpeg_path: /usr/bin/ffmpeg

```

## Dependencies
N/A

## Example Group Variables
This config contains most of the configurable options available to the user.  Customizing these options beyond the defaults or examples given is beyond the scope of this documentation, however the examples cover basic through advanced customizations for reference purposes.

```yaml
nginx_accesslog_grokpattern: '%{CLIENT:client_ip} - %{NOTSPACE:ident} \[%{HTTPDATE:ts:ts-httpd}\] %{NOTSPACE:request_host:tag} "(?:%{WORD:verb:tag} %{NOTSPACE:request} (?:HTTP/%{NUMBER:http_version:float})?|%{DATA})" %{NUMBER:resp_code:tag} (?:%{NUMBER:resp_bytes:int}|-) "%{NOTSPACE:referrer}" "%{DATA:agent:tag}" (?:%{NUMBER:request_time}|-) (?:%{NUMBER:upstream_connect_time}|-) %{NOTSPACE:x_forwarded_for} %{NOTSPACE:upstream_cache_status:tag}'
fail2ban_banlog_grokpattern: '%{TIMESTAMP_ISO8601:timestamp} %{WORD:log_src}.%{WORD:src_action} *\[%{INT:fail2ban_digit}\]: %{WORD:loglevel:tag} *\[%{NOTSPACE:service:tag}\] %{GREEDYDATA:ban_status:tag} %{IP:clientip:tag}'
nginx_proxy_cache_regex: '~* (^/(photo|media|image|images|mediacover|pms_image_proxy)|\.(?:jpg|jpeg|gif|png|ico|cur|gz|svg|svgz|mp4|ogg|ogv|webm|htc|css|js)$)'

fail2ban_enable: True
fail2ban_bantime: "1h"
fail2ban_findtime: "10m"
fail2ban_maxretry: "2"
fail2ban_usedns: "raw"
fail2ban_logtarget: /var/log/fail2ban.log
fail2ban_banaction: pfsense
fail2ban_pfsense_ip: "10.0.10.1"
fail2ban_pfsense_user: fail2ban
fail2ban_ssh_private_key: "{{ vault_fail2ban_ssh_private_key }}"

fail2ban_services:
  - name: nginx-http-auth
    enabled: True
    filter: nginx-http-auth
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-noscript
    enabled: True
    filter: nginx-noscript
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-badbots
    enabled: True
    filter: nginx-badbots
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-botsearch
    enabled: True
    filter: nginx-botsearch
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-nohome
    enabled: True
    filter: nginx-nohome
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-404
    enabled: True
    filter: nginx-404
    port: http,https
    logpath: /var/log/nginx/home*.log
  - name: nginx-401
    enabled: True
    filter: nginx-401
    port: http,https
    findtime: '1m'
    bantime: '5m'
    maxretry: 3
    logpath:
      - /var/log/nginx/ombi*.log
      - /var/log/nginx/plex*.log
      - /var/log/nginx/tautulli*.log
      - /var/log/nginx/stats*.log
      - /var/log/nginx/ci*.log
      - /var/log/nginx/repo*.log
      - /var/log/nginx/eddie*.log

nginx_enable_rtmp: True
nginx_rtsp_camera_feed: 'rtsp://<campera_ip>:<rstp_port>/<token>'
nginx_hls_camera_feed_transcode_dir: /data/public_html/aquarium
nginx_rtmp_listen_port: 1935
nginx_rtsp_transport_proto: tcp
nginx_hls_camera_transcode_index: "index.{{ nginx_hls_segment_list_type }}"
nginx_hls_camera_transcode_path: "{{ nginx_hls_camera_feed_transcode_dir }}/{{ nginx_hls_camera_transcode_index }}"
nginx_hls_segment_list_type: m3u8
nginx_hls_segment_format: mpegts
nginx_hls_segment_list_entry_prefix: /
nginx_fflags: |
  nobuffer -rtsp_transport tcp -i {{ nginx_rtsp_camera_feed }} \
  -vsync 0 -copyts -vcodec copy \
  -movflags frag_keyframe+empty_moov -an \
  -hls_flags delete_segments+append_list \
  -f segment -segment_list_flags live \
  -segment_time 15 -segment_list_size 10 -segment_format {{ nginx_hls_segment_format }} \
  -segment_list {{ nginx_hls_camera_transcode_path }} \
  -segment_list_type {{ nginx_hls_segment_list_type }} \
  -segment_list_entry_prefix {{ nginx_hls_segment_list_entry_prefix }} \
  {{ nginx_hls_camera_feed_transcode_dir }}/%d.ts > /var/log/ffmpeg 2>&1

nginx_rtmp_ffmpeg_command: "{{ nginx_ffmpeg_path }} -fflags {{ nginx_fflags }}"

nginx_index:
  - 'index.php'
  - 'index.html'
  - 'index.htm'
  - 'index.m3u8'

nginx_module_pkgs:
  - libnginx-mod-http-fancyindex
  - libnginx-mod-rtmp

nginx_modules_enabled:
  - ngx_http_fancyindex_module.so
  - ngx_rtmp_module.so


nginx_backends:

  - service: sabnzbd
    servers:
      - <ip_address>:<port>

  - service: ombi
    servers:
      - <ip_address>:<port>

  - service: sonarr
    servers:
      - <ip_address>:<port>

  - service: radarr
    servers:
      - <ip_address>:<port>

  - service: grafana
    servers:
      - <ip_address>:<port>

  - service: tautulli
    servers:
      - <ip_address>:<port>

  - service: bazarr
    servers:
      - <ip_address>:<port>

  - service: plex
    servers:
      - <ip_address>:<port>

  - service: automation
    servers:
      - <ip_address>:<port>

nginx_vhosts:

##### Internally accessible NON-SSL vhosts

  - servername: localhost;
    serverlisten: 80;
    locations:
      - name: /nginx_status
        extra_parameters: |
          stub_status;
          access_log off;
          allow 127.0.0.1;
          deny all;
          
  - servername: "home.example.com"
    serveralias: "example.com www.home.example.com {{ ansible_eth0.ipv4.address }}"
    serverlisten: "80 default_server"
    locations:
      - name: /
        docroot: "{{ data_mount_root }}/{{ www_directory }}"
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

  - servername: automation.home.example.com
    serveralias: automation
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: automation
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "upgrade";
          proxy_set_header        upgrade             $http_upgrade;
      - name: /api/websocket
        proxy: "wws://"
        backend: automation/api/websocket
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "Upgrade";
          proxy_set_header        Upgrade             "WebSocket";
          
  - servername: stats.home.example.com
    serveralias: stats
    serverlisten: "80"
    locations:
      - name: /
        proxy: True
        backend: grafana
        custom_css: grafana/graforg.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: grafana
        proxy_cache: True
      - name: favicon.ico
        docroot: "{{ nginx_default_docroot }}"
        proxy: True
        backend: grafana
        proxy_cache: True


  - servername: sabnzbd.home.example.com
    serveralias: sabnzbd
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: sabnzbd
        custom_css: sabnzbd_dark.css

  - servername: sonarr.home.example.com
    serveralias: sonarr
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: sonarr
        custom_css: sonarr/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: sonarr

  - servername: radarr.home.example.com
    serveralias: radarr
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: radarr
        proxy_cache: True
        custom_css: radarr/dark.css
        extra_parameters: |
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection $http_connection;
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: radarr

  - servername: bazarr.home.example.com
    serveralias: bazarr
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: bazarr
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: bazarr
        proxy_cache: True

  - servername: ombi.home.example.com
    serveralias: ombi
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: ombi
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: ombi

  - servername: tautulli.home.example.com
    serveralias: tautulli
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: tautulli
        proxy_cache: False
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: tautulli

  - servername: plex.home.example.com
    serveralias: plex
    serverlisten: 80
    locations:
      - name: /
        proxy: True
        backend: plex
#        custom_css: plex/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: plex


##### Externally accessible SSL vhosts

  - servername: "home.example.com"
    serveralias: "example.com www.home.example.com www.example.com {{ ansible_eth0.ipv4.address }}"
    serverlisten: "8080 default_server"
    locations:
      - name: /
        docroot: "{{ data_mount_root }}/{{ www_directory }}"
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


  - servername: ombi.example.com
    serveralias: ombi
    serverlisten: "8080"
    locations:
      - name: /
        proxy: True
        backend: ombi
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: ombi

  - servername: tautulli.example.com
    serveralias: tautulli
    serverlisten: 8080
    locations:
      - name: /
        proxy: True
        backend: tautulli
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: tautulli

  - servername: plex.example.com
    serveralias: plex
    serverlisten: "8080"
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: plex
#        custom_css: plex/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: plex

  - servername: stats.example.com
    serveralias: stats
    serverlisten: 8080
    locations:
      - name: /
        proxy: True
        backend: grafana
        custom_css: grafana/graforg.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: grafana
        proxy_cache: True
      - name: favicon.ico
        docroot: "{{ nginx_default_docroot }}"
        proxy: True
        backend: grafana
        proxy_cache: True

  - servername: aquarium.example.com
    serveralias: aquarium
    serverlisten: 8080
    locations:
      - name: /
        docroot: /data/public_html/aquarium
        proxy: False
        extra_parameters: |
          types {
            application/vnd.apple.mpegurl m3u8;
            video/mp2t ts;
            }
          add_header Cache-Control no-cache;


nginx_vhosts_ssl:

##### Internally accessible SSL vhosts

  - servername: "home.example.com"
    serveralias: "example.com www.example.com www.home.example.com"
    serverlisten: "443 default_server"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        docroot: "{{ data_mount_root }}/{{ www_directory }}"
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

  - servername: stats.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: grafana
        custom_css: grafana/graforg.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: grafana
        proxy_cache: True
      - name: favicon.ico
        docroot: "{{ nginx_default_docroot }}"
        proxy: True
        backend: grafana
        proxy_cache: True

  - servername: aquarium.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        docroot: /data/public_html/aquarium
        proxy: False
        extra_parameters: |
          types {
            application/vnd.apple.mpegurl m3u8;
            video/mp2t ts;
            }
          add_header Cache-Control no-cache;



  - servername: automation.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: automation
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "Upgrade";
          proxy_set_header        upgrade             $http_upgrade;
      - name: /api/websocket
        proxy: True
        backend: automation/api/websocket
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "Upgrade";
          proxy_set_header        Upgrade             "WebSocket";

  - servername: sabnzbd.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: sabnzbd
        custom_css: sabnzbd_dark.css

  - servername: sonarr.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: sonarr
        custom_css: sonarr/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: sonarr

  - servername: radarr.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: radarr
        custom_css: radarr/dark.css
        extra_parameters: |
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection $http_connection;
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: radarr

  - servername: bazarr.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: bazarr
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: bazarr
        proxy_cache: True

  - servername: ombi.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: ombi
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: ombi

  - servername: tautulli.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: False
        backend: tautulli
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: tautulli

  - servername: plex.home.example.com
    serverlisten: "443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: plex
#        custom_css: plex/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: plex

# Externally accessible SSL vhosts

  - servername: "home.example.com"
    serveralias: "example.com www.example.com www.home.example.com"
    serverlisten: "8443 default_server"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        docroot: "{{ data_mount_root }}/{{ www_directory }}"
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

  - servername: aquarium.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        docroot: /data/public_html/aquarium
        proxy: False
        extra_parameters: |
          types {
            application/vnd.apple.mpegurl m3u8;
            video/mp2t ts;
            }
          add_header Cache-Control no-cache;

  - servername: ombi.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: ombi
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: ombi

  - servername: automation.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: automation
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "upgrade";
          proxy_set_header        upgrade             $http_upgrade;
      - name: /api/websocket
        proxy: True
        backend: automation/api/websocket
        extra_parameters: |
          proxy_http_version         1.1;
          proxy_set_header       Connection          "Upgrade";
          proxy_set_header        Upgrade             "WebSocket";

          
  - servername: tautulli.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: False
        backend: tautulli
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: tautulli

  - servername: plex.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        proxy_cache: True
        backend: plex
#        custom_css: plex/dark.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        proxy_cache: True
        backend: plex

  - servername: stats.example.com
    serverlisten: "8443"
    ssl_certchain: "{{ ssl_certchain }}"
    ssl_privkey: "{{ ssl_privkey }}"
    ssl_certpath: "{{ ssl_certpath }}"
    ssl_keypath: "{{ ssl_keypath }}"
    locations:
      - name: /
        proxy: True
        backend: grafana
        custom_css: grafana/graforg.css
      - name: "{{ nginx_proxy_cache_regex }}"
        proxy: True
        backend: grafana
        proxy_cache: True
      - name: favicon.ico
        docroot: "{{ nginx_default_docroot }}"
        proxy: True
        backend: grafana
        proxy_cache: True


telegraf_plugins_extra:

  - name: nginx
    options:
      urls:
        - "http://localhost/nginx_status"
  - name: procstat
    options:
      pattern: "nginx"
      prefix: "nginx"
  - name: x509_cert
    options:
      interval: "1m"
      sources:
        - 'https://www.example.com:443'
        - 'https://plex.home.example.com:443'
        - 'https://automation.home.example.com:443'

## Example Telegraf 'logparser' inputs for nginx logs and fail2ban logs
  - name: logparser
    options:
      files:
        - "/var/log/nginx/*.log"
      from_beginning: "false"
      grok:
        patterns:
          - '{{ nginx_accesslog_grokpattern }}'
        measurement: nginx_access_log
  - name: logparser
    options:
    files:
      - "/var/log/fail2ban.log"
    from_beginning: "false"
    grok:
      patterns:
        - '{{ fail2ban_banlog_grokpattern }}'
      measurement: fail2ban_log
  - name: fail2ban
    options:
      use_sudo: "false"


```

## Example Playbook

```yaml
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
