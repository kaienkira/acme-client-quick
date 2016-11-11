# acme-client-quick
Get Let's Encrypt Cert In Five Minutes

* It's a Quick and Dirty method, For security and detail guide please READ
  https://github.com/kaienkira/acme-client
* Tested only in Ubuntu and CentOS

# Steps
# get dependency
```
# Ubuntu
sudo apt-get install php-cli php-curl nginx

# CentOS
yum install php-cli php-curl nginx
```

## put your domain name in domain.txt
```
cd acme-client-quick
echo "example.com" >> domain.txt
echo "www.example.com" >> domain.txt
```

## get cert
```
# need root because http-01 challenge need listen 80 port
# make sure your system 80 port is free
# maybe you need run
# sudo service nginx stop first
sudo ./quick-start.sh
```

## result file
```
cd cert

# ssl.key -- your domain private key
# ssl.crt -- your domain cert

# nginx config
# ...
# ssl_certificate /path/to/ssl.crt;
# ssl_certificate_key /path/to/ssl.key;
# ...
```
