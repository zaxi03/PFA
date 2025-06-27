apt-get update && apt-get install -y build-essential autoconf automake libtool pkgconf git wget libxml2-dev libpcre3-dev libyajl-dev libcurl4-openssl-dev libgeoip-dev liblmdb-dev zlib1g-dev libxslt1-dev liblua5.3-dev ca-certificates libpcre2-dev libssl-dev
apt install git
cd /opt && git clone https://github.com/SpiderLabs/ModSecurity
cd ModSecurity
git submodule init
git submodule update
./build.sh
./configure
make
make install
cd /opt && git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git
cd /opt && wget http://nginx.org/download/nginx-$(nginx -v 2>&1 | cut -d'/' -f2).tar.gz
tar -xvzmf nginx-$(nginx -v 2>&1 | cut -d'/' -f2).tar.gz
cd nginx-$(nginx -v 2>&1 | cut -d'/' -f2)
./configure --add-dynamic-module=../ModSecurity-nginx --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/run/nginx.pid --lock-path=/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-http_v3_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --with-cc-opt='-g -O2 -ffile-prefix-map=/home/builder/debuild/nginx-1.27.5/debian/debuild-base/nginx-1.27.5=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie'
make modules
cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules
#sed -i '1i\load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf
rm -rf /usr/share/modsecurity-crs
git clone https://github.com/coreruleset/coreruleset /usr/local/modsecurity-crs
#mv /usr/local/modsecurity-crs/crs-setup.conf.example /usr/local/modsecurity-crs/crs-setup.conf
mv /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /usr/local/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
mv /usr/local/modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example /usr/local/modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
touch /usr/local/modsecurity-crs/rules/modsecurity_crs_15_customrules.conf
mkdir -p /etc/nginx/modsec
cp /opt/ModSecurity/unicode.mapping /etc/nginx/modsec
#cp /opt/ModSecurity/modsecurity.conf-recommended /etc/nginx/modsec
#cp /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
#sed -i 's/^SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf
touch /etc/nginx/modsec/main.conf
cat <<EOF > /etc/nginx/modsec/main.conf
Include /etc/nginx/modsec/modsecurity.conf
Include /usr/local/modsecurity-crs/crs-setup.conf
Include /usr/local/modsecurity-crs/rules/*.conf
EOF

