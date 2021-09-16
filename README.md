# RockyLinux 8 + PHP 7.4 + MariaDB 10.5
## 인터넷이 연결되어 있지 않은 경우
```shell
vi /etc/sysconfig/network-scripts/ifcfg-enp0s3 

## 아래라인 추가
DNS1="168.126.63.1" 

systemctl restart NetworkManager

## resolv.conf 파일 생성된 것 확인.
cat /etc/resolv.conf
```

## 보안 및 업데이트
```shell
dnf update
```

## Development Tool Install
기본적인 서버 개발툴 설치 작업
```shell
dnf groupinstall -y "Development Tools"
```

## 기본 필요 툴 설치
```shell
dnf config-manager --set-enabled powertools

dnf install -y ntsysv lynx
```

## SELinux Disable
```shell
vi /etc/selinux/config
# 위 파일에서 아래 라인 수정
SELINUX=disabled

# 수정후 재부팅
shutdown -r now
```

## Firewall
```shell
firewall-cmd --zone=public --add-service=http
firewall-cmd --zone=public --add-service=https
firewall-cmd --zone=public --add-service=ssh
firewall-cmd --list-all

```

## NTP(chrony) Install
```shell
dnf install -y chrony

vi /etc/chrony.conf 
# 위 파일에서 기존 server 셋팅 라인 삭제 후 아래 라인 추가

pool kr.pool.ntp.org iburst
pool time.bora.net iburst
pool time.nuri.net iburst
pool time.kriss.re.kr iburst
pool time.nist.gov iburst
pool time.kornet.net iburst

systemctl enable chronyd
systemctl start chronyd

chronyc sources 
chronyc tracking
timedatectl status
```

## PHP 7 설치
```shell
# epel 저장소 설치
dnf install -y epel-release dnf-utils

# Remi repository 설치 
rpm -Uvh https://rpms.remirepo.net/enterprise/remi-release-8.rpm

# PHP 7.4 활성화
dnf module enable php:remi-7.4

# PHP 7 + Module 설치
dnf install -y php-fpm php-devel php-json php-mbstring php-opcache php-pdo php-pecl-geoip php-pecl-imagick php-tidy php-xml php-gd php-mysql php-pecl-zip php-ioncube-loader php-curl

systemctl enable php-fpm
```

## PHP 설정
```shell
vi /etc/php.ini
```

```ini
# 파일 안에서 아래 부분 수정
expose_php = Off
upload_max_filesize = 200M
max_file_uploads = 100
post_max_size = 800M
date.timezone = Asia/Seoul
browscap = /etc/php_browscap.ini
```

```shell
# browscap 파일 다운로드 
# Full
wget http://browscap.org/stream?q=Full_PHP_BrowsCapINI -O /etc/php_browscap.ini

# Lite
wget http://browscap.org/stream?q=Lite_PHP_BrowsCapINI -O /etc/php_browscap.ini

# Standard
wget http://browscap.org/stream?q=PHP_BrowsCapINI -O /etc/php_browscap.ini

# php-fpm 서비스 시작
systemctl start php-fpm
```

## Oracle Client 설치
PHP + ORACLE 연동이 필요한 경우 해당 절차 진행
* Oracle Client Basic
* Oracle Client Devel
위 두가지 버전 다운받아 설치
ex ) rpm -Uvh oracleclient.rpm
```shell
# 아래 파일 작성
vi /etc/ld.so.conf.d/oracle-instantclient.conf 

# 내용에 아래 내용 추가 (해당 위치 확인 후 버전 숫자 수정)
/usr/lib/oracle/xx.x/client64/lib

# 아래 라인 실행 
ldconfig

# php oci 설치
dnf install -y php-oci
dnf install -y libnsl

# php-fpm 재시작
systemctl restart php-fpm
```

## NGINX 설치
```shell
vi /etc/yum.repos.d/nginx.repo

# repo 파일에 아래 내용 입력
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true

dnf module reset nginx
dnf module enable nginx:mainline
dnf install nginx
dnf info nginx 
# 위 명령 실행후 설치된 Version 확인

# 같은 버전의 nginx의 소스를 다운로드
cd ~
wget http://nginx.org/download/nginx-1.19.2.tar.gz 

tar xvzf nginx-1.19.2.tar.gz 
```

## NGINX Module 설치
* gzip 같은 컨텐츠 압축 전달을 위한 brotli 모듈
* nginx 헤더에 보안 옵션을 컨트롤 하기 위한 모듈 2가지
* 컨텐츠의 최적화된 전달을 위한 pagespeed 모듈
이렇게 3가지 모듈을 추가적으로 컴파일하여 설치하도록 함.

```shell
cd ~

# https://github.com/openresty/headers-more-nginx-module/tags
# 위 주소에서 최신버전 다운로드
wget https://github.com/openresty/headers-more-nginx-module/archive/v0.33.tar.gz -O headers-more-nginx-module-0.33.tar.gz
tar xvzf headers-more-nginx-module-0.33.tar.gz
 
# https://github.com/GetPageSpeed/ngx_security_headers/tags
# 위 주소에서 최신버전 다운로드
wget https://github.com/GetPageSpeed/ngx_security_headers/archive/0.0.9.tar.gz -O ngx_security_headers-0.0.9.tar.gz
tar xvzf ngx_security_headers-0.0.9.tar.gz

# Brotli 
dnf install brotli brotli-devel
wget https://github.com/google/ngx_brotli/archive/master.zip -O ngx_brotli-master.zip
unzip ngx_brotli-master.zip

# pagespeed
wget https://github.com/apache/incubator-pagespeed-ngx/archive/latest-stable.tar.gz -O incubator-pagespeed-ngx-latest-stable.tar.gz
tar xvzf incubator-pagespeed-ngx-latest-stable.tar.gz

cd ~/incubator-pagespeed-ngx-latest-stable
wget https://dl.google.com/dl/page-speed/psol/1.13.35.2-x64.tar.gz
tar xzvf 1.13.35.2-x64.tar.gz

# 컴파일
cd ~
dnf install gcc-c++ pcre-devel zlib-devel make unzip libuuid-devel libxslt libxslt-devel gd-devel perl-ExtUtils-Embed gperftools

cd ~/nginx-1.19.2

# yum 패키지로 설치되어있는 nginx 의 compile 옵션을 확인 후 그대로 이용해야함
nginx -V # 실행 후 configure arguments 를 복사 후 이용

 --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie'

# 위의 명령어 뒤에 아래 라인 추가해서 ./configure 실행
--add-dynamic-module=/root/headers-more-nginx-module-0.33 --add-dynamic-module=/root/ngx_security_headers-0.0.9 --add-dynamic-module=/root/ngx_brotli-master --add-dynamic-module=/root/incubator-pagespeed-ngx-latest-stable

# ./configure 실행
./configure (복사한 옵션) (추가된 옵션)

# 아래 입력창 나오면 Y
Use the available Release binaries? [Y/n] Y

# 모듈 컴파일
make
## 주의 : make install 은 하지 말것. 혹시나 모르는 상황 대비
## make install 할 경우 기존에 설치되어있던 파일도 덮어쓰게 됨.

## 컴파일된 모듈 nginx 폴더로 복사
mkdir /usr/share/nginx/modules
cp ./objs/*.so /usr/share/nginx/modules

## 서비스 등록
systemctl enable nginx
```

## NGINX Module 설정
아래 파일 생성
vi /etc/nginx/pagespeed.conf

```nginx
pagespeed on;
pagespeed FileCachePath "/var/cache/ngx_pagespeed/";
pagespeed EnableFilters collapse_whitespace;
```

## NGINX 설정
vi /etc/nginx/nginx.conf

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log crit;
pid /run/nginx.pid;

worker_rlimit_nofile 100000;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

load_module "modules/ngx_http_headers_more_filter_module.so";
load_module "modules/ngx_http_brotli_static_module.so";
load_module "modules/ngx_http_brotli_filter_module.so";
load_module "modules/ngx_http_security_headers_module.so";
load_module "modules/ngx_pagespeed.so";

events {
    worker_connections 4000;
    use epoll;
    multi_accept on;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    open_file_cache max=200000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors on;

    client_max_body_size 200M;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    types_hash_max_size 2048;
    
    brotli on;
    brotli_static on;        # for static compression, explained later
    brotli_comp_level 11;    # this setting can vary from 1-11
    brotli_types text/plain text/css application/javascript application/json image/svg+xml application/xml+rss;
    
    gzip on;
    gzip_comp_level 6;
    gzip_vary on;
    gzip_min_length 100;
    gzip_proxied any;
    gzip_types application/octet-stream text/plain text/css application/json application/x-javascript application/javascript text/xml application/xml application/rss+xml text/javascript image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype;
    gzip_disable "msie6";

    # allow the server to close connection on non responding client, this will free up memory
    reset_timedout_connection on;

    # request timed out -- default 60
    client_body_timeout 10;

    # if client stop responding, free up memory -- default 60
    send_timeout 2;

    # server will close connection after this time -- default 75
    keepalive_timeout 30;

    # number of requests client can make over keep-alive -- for testing environment
    keepalive_requests 100000;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    include /etc/nginx/pagespeed.conf;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}

```

vi /etc/nginx/security.conf

```nginx
server_tokens off;

security_headers on;
hide_server_tokens on;
security_headers_xss block;
security_headers_frame sameorigin;
security_headers_referrer_policy same-origin;
security_headers_nosniff_types text/javascript application/javascript;

add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' *.mainpay.co.kr *.kakao.com *.daumcdn.net ajax.googleapis.com developers.kakao.com www.googletagmanager.com wcs.naver.net browser-update.org www.google-analytics.com;img-src 'self' data: *.daumcdn.net wcs.naver.com www.google-analytics.com www.googletagmanager.com; style-src 'self' 'unsafe-inline' fonts.googleapis.com; font-src 'self' cdn.jsdelivr.net fonts.gstatic.com; frame-src 'self' *.mainpay.co.kr *.daum.net; object-src 'none'";

add_header X-Robots-Tag none;
add_header X-Download-Options noopen;
add_header X-Permitted-Cross-Domain-Policies none;
add_header Access-Control-Allow-Origin "http://$host https://$host";
```


/etc/nginx/conf.d/www.conf 파일 생성
```nginx
server {
        listen       80 default_server;
        server_name  _ www.DOMAIN.COM;

        #아래 라인은 https 강제 전환시 사용
        #return         301 https://$host$request_uri;

        error_log /var/log/nginx/USER.error error;
        access_log /var/log/nginx/USER.access combined;
        root        /home/USER/src;
        index           index.php index.html;

        error_page 400 401 402 403 404 405 /400;
        
        include /etc/nginx/security.conf;
        
        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }
    
        location ~ /(\.ht|\.git|\.svn) {
            access_log off;
            log_not_found off;
            deny  all;
        }
    
        location ~* \.(js|less|css)$ {
            add_header X-Content-Type-Options "nosniff" always;
            include /etc/nginx/security.conf;
            access_log off;
            log_not_found off;
            expires max;
    	  }
    
        location ~* \.(js|less|css|png|jpg|jpeg|gif|ico|svg|wav|swf|eot|ttf|otf|woff|woff2|flv|mp3|mp4|xml)$ {
            access_log off;
            log_not_found off;
            expires max;
    	  }

        location ~ \.php$ {
                try_files      $uri =404;
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass   php-fpm;
                fastcgi_index  index.php;
                fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
                include        fastcgi_params;
        }
}

## 아래는 SSL 사용시 추가
server {
        listen       443 http2;
        server_name  www.DOMAIN.COM;
        error_log /var/log/nginx/USER.ssl.error error;
        access_log /var/log/nginx/USER.ssl.access combined;
        root        /home/USER/src;
        index           index.php index.html;

        ssl on;
        ssl_certificate      /etc/letsencrypt/live/www.DOMAIN.COM/fullchain.pem;
        ssl_certificate_key  /etc/letsencrypt/live/www.DOMAIN.COM/privkey.pem;
        ssl_session_cache shared:SSL:1m;
        ssl_session_timeout  10m;
        ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
        ssl_ciphers HIGH:SEED:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!RSAPSK:!aDH:!aECDH:!EDH-DSS-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA:!SRP;
        ssl_prefer_server_ciphers   on;

        error_page 400 401 402 403 404 405 /400;
        
        include /etc/nginx/default.d/security.conf;
        
        location / {
            try_files $uri $uri/ /index.php$is_args$args;
        }
    
        location ~ /(\.ht|\.git|\.svn) {
            access_log off;
            log_not_found off;
            deny  all;
        }
    
        location ~* \.(js|less|css)$ {
            add_header X-Content-Type-Options "nosniff" always;
            include /etc/nginx/security.conf;
            access_log off;
            log_not_found off;
            expires max;
    	  }
    
        location ~* \.(js|less|css|png|jpg|jpeg|gif|ico|svg|wav|swf|eot|ttf|otf|woff|woff2|flv|mp3|mp4|xml)$ {
            access_log off;
            log_not_found off;
            expires max;
    	  }
    	  
        location ~ \.php$ {
                try_files      $uri =404;
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                fastcgi_pass   php-fpm;
                fastcgi_index  index.php;
                fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
                include        fastcgi_params;
        }
}

```

```shell
# nginx 서비스 시작
systemctl start nginx
```

## MariaDB 설치
[MariaDB - Setting up MariaDB Repositories         - MariaDB](https://downloads.mariadb.org/mariadb/repositories)
위 Repo 주소 확인하여 아래 내용 적용
```shell
vi /etc/yum.repos.d/MariaDB.repo

# 아래 내용 입력
# MariaDB 10.5 CentOS repository list - created 2020-10-19 06:52 UTC
# http://downloads.mariadb.org/mariadb/repositories/
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.5/centos8-amd64
module_hotfixes=1
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1

# 설치
yum install -y MariaDB-server MariaDB-client

# 서비스 시작
systemctl start mariadb

# root 비밀번호 설정
/usr/bin/mysqladmin -u root password 'password'

# 서비스 등록
systemctl enable mariadb
```
