#!/usr/bin/env php
<?php

class Config
{
    // debug use
    // public static $acme_url_base = 'https://acme-staging.api.letsencrypt.org';
    // prod use
    public static $acme_url_base = 'https://acme-v01.api.letsencrypt.org';
}

function printUsage($prog_name)
{
    echo "usage: $prog_name ".
         '-a <account_key_file> '.
         '-r <csr_file> '.
         '-d <domain_list(domain1;domain2...;domainN)> '.
         '-c <http_challenge_dir> '.
         '-o <output_cert_file>'.
         '[-t <terms_of_service>]'.
         "\n";
}

function urlbase64($bin)
{
    return str_replace(
        array('+', '/', '='),
        array('-', '_', ''),
        base64_encode($bin));
}

function loadAccountKey($account_key_file)
{
    $key_file_content = file_get_contents($account_key_file);
    if ($key_file_content === false) {
        echo "can not open file: $account_key_file\n";
        return false;
    }
    $key = openssl_pkey_get_private($key_file_content);
    if ($key === false) {
        echo "openssl failed: ".openssl_error_string()."\n";
        return false;
    }

    return $key;
}

function loadCsrFile($csr_file)
{
    $csr_file_content = file_get_contents($csr_file);
    if ($csr_file_content === false) {
        echo "can not open file: $csr_file_content\n";
        return false;
    }
    $lines = explode("\n", $csr_file_content);
    unset($lines[0]);
    unset($lines[count($lines) - 1]);
    return urlbase64(base64_decode(implode('', $lines)));
}

function getAccountKeyInfo($key)
{
    $key_info = openssl_pkey_get_details($key);
    if ($key_info === false) {
        echo "openssl failed: ".openssl_error_string()."\n";
        return false;
    }
    if (!isset($key_info['rsa'])) {
        echo "account key file is not rsa private key\n";
        return false;
    }

    return array(
        'e' => urlbase64($key_info['rsa']['e']),
        'n' => urlbase64($key_info['rsa']['n']),
    );
}

function getThumbPrint($key)
{
    $key_info = getAccountKeyInfo($key);
    if ($key_info === false) {
        return false;
    }

    $thumb_print = array(
        'e' => $key_info['e'],
        'kty' => 'RSA',
        'n' => $key_info['n'],
    );
    $thumb_print = urlbase64(openssl_digest(
        json_encode($thumb_print), "sha256", true));

    return $thumb_print;
}

function signMessage($key, $message)
{
    if (openssl_sign($message, $sign, $key, 'sha256') === false) {
        return false;
    }

    return urlbase64($sign);
}

function httpRequest($url, $method, $post_data = '')
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);

    $method = strtolower($method);
    if ($method === 'head') {
        // head method
        curl_setopt($ch, CURLOPT_NOBODY, true);
    } else if ($method === 'get') {
        // get method
    } else if ($method === 'post') {
        // post method
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
    } else {
        echo "curl_failed: invalid http method\n";
        return false;
    }

    $output = curl_exec($ch);
    if ($output === false) {
        echo 'curl failed: '.curl_error($ch)."\n";
        return false;
    }
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($output, 0, $header_size);
    $response = substr($output, $header_size);

    curl_close($ch);

    return array(
        'http_code' => $http_code,
        'header' => $header,
        'response' => $response,
    );
}

function getReplayNonce()
{
    $ret = httpRequest(Config::$acme_url_base.'/directory', 'head');
    if ($ret === false) {
        return false;
    }

    preg_match('/^replay-nonce: (.*?)\r\n/sm', $ret['header'], $matches);
    if (!isset($matches[1])) {
        echo "curl failed: replay nonce header is missing\n";
        return false;
    }

    return $matches[1];
}

function signedHttpRequest($key, $url, $payload)
{
    $nonce = getReplayNonce();
    if ($nonce === false) {
        return false;
    }

    $key_info = getAccountKeyInfo($key);
    if ($key_info === false) {
        return false;
    }

    // header
    $header = array(
        'alg' => 'RS256',
        'jwk' => array(
            'kty' => 'RSA',
            'e' => $key_info['e'],
            'n' => $key_info['n'],
        ),
    );

    // protected
    $protected = $header;
    $protected['nonce'] = $nonce;

    $payload64 = urlbase64(json_encode($payload));
    $protected64 = urlbase64(json_encode($protected));
    $sign = signMessage($key, $protected64.'.'.$payload64);
    if ($sign === false) {
        return false;
    }

    $request_data = array(
        'header' => $header,
        'protected' => $protected64,
        'payload' => $payload64,
        'signature' => $sign,
    );
    $request_data = json_encode($request_data);

    return httpRequest($url, 'post', $request_data);
}

function registerAccount($key, $tos)
{
    // get lastest tos
    $ret = httpRequest(Config::$acme_url_base.'/terms', 'get');
    if ($ret === false) {
        return false;
    }
    preg_match('/^<a href="(.*?)">/sm', $ret['response'], $matches);
    if (!isset($matches[1])) {
        echo "acme/new-reg failed: get lastest tos failed\n";
        return false;
    }
    $latest_tos = $matches[1];

    if ($tos != '' && $tos != $latest_tos) {
        echo "terms of service has changed: ".
             "please modify your -t command option\n".
             "new tos: $latest_tos\n";
        return false;
    }

    // register account
    $ret = signedHttpRequest($key,
        Config::$acme_url_base.'/acme/new-reg', array(
        'resource' => 'new-reg',
        'agreement' => $latest_tos,
    ));
    if ($ret === false) {
        return false;
    }
    // 201 - register successfully
    // 409 - already registered
    if ($ret['http_code'] != 201 &&
        $ret['http_code'] != 409) {
        echo 'acme/new-reg failed: '.$ret['response']."\n";
        return false;
    }

    return true;
}

function domainChallenge($key, $domain,
    $http_challenge_dir, $thumb_print)
{
    $ret = signedHttpRequest($key,
        Config::$acme_url_base."/acme/new-authz", array(
        'resource' => 'new-authz',
        'identifier' => array(
            'type' => 'dns',
            'value' => $domain,
        ),
    ));
    if ($ret === false) {
        return false;
    }
    if ($ret['http_code'] != 201) {
        echo 'acme/new-authz failed: '.$ret['response']."\n";
        return false;
    }

    $response = json_decode($ret['response'], true);
    $challenges = $response['challenges'];

    foreach ($challenges as $challenge) {
        if ($challenge['type'] != 'http-01') {
            continue;
        }
        $challenge_token = $challenge['token'];
        $challenge_uri = $challenge['uri'];
        $challenge_key_auth = $challenge_token.'.'.$thumb_print;

        if (file_put_contents(
                "$http_challenge_dir/$challenge_token",
                $challenge_key_auth) === false) {
            return false;
        }

        $ret = signedHttpRequest($key,
            $challenge_uri, array(
            'resource' => 'challenge',
            'keyAuthorization' => $challenge_key_auth,
        ));
        if ($ret === false) {
            return false;
        }
        if ($ret['http_code'] != 202) {
            echo 'acme/challenge failed: '.$ret['response']."\n";
            return false;
        }

        // wait to be verified
        for (;;) {
            $ret = httpRequest($challenge_uri, 'get');
            if ($ret === false) {
                return false;
            }
            $response = json_decode($ret['response'], true);
            if (!isset($response['status']) ||
                $response['status'] == 'invalid') {
                echo 'acme/challenge failed: '.$ret['response']."\n";
                return false;
            }
            if ($response['status'] == 'pending') {
                sleep(2);
                continue;
            } else if ($response['status'] == 'valid') {
                return true;
            }
        }
    }

    return true;
}

function issueCert($key, $csr, $output_cert_file)
{
    // get cert
    $ret = signedHttpRequest($key,
        Config::$acme_url_base."/acme/new-cert", array(
        'resource' => 'new-cert',
        'csr' => $csr,
    ));
    if ($ret === false) {
        return false;
    }
    if ($ret['http_code'] != 201) {
        echo 'acme/new-cert failed: '.$ret['response']."\n";
        return false;
    }
    $cert = base64_encode($ret['response']);

    // get intermediate cert
    preg_match('/^link: <(.*?)>;rel="up"\r\n/sm', $ret['header'], $matches);
    if (!isset($matches[1])) {
        echo "acme/new-cert failed: can not get intermediate cert url\n";
        return false;
    }
    $ret = httpRequest($matches[1], 'get');
    if ($ret === false) {
        return false;
    }
    if ($ret['http_code'] != 200) {
        echo "acme/new-cert failed: can not get intermediate cert\n";
        return false;
    }
    $intermediate_cert = base64_encode($ret['response']);

    if (file_put_contents($output_cert_file,
            "-----BEGIN CERTIFICATE-----\n".
            chunk_split($cert, 64, "\n").
            "-----END CERTIFICATE-----\n".
            "-----BEGIN CERTIFICATE-----\n".
            chunk_split($intermediate_cert, 64, "\n").
            "-----END CERTIFICATE-----\n") === false) {
        return false;
    }

    return true;
}

function main($argc, $argv)
{
    $prog_name = basename($argv[0]);
    $cmd_options = getopt('a:r:d:c:o:t:');
    if (!isset($cmd_options['a']) ||
        !isset($cmd_options['r']) ||
        !isset($cmd_options['d']) ||
        !isset($cmd_options['c']) ||
        !isset($cmd_options['o'])) {
        printUsage($prog_name);
        return false;
    }

    $account_key_file = $cmd_options['a'];
    $csr_file = $cmd_options['r'];
    $domain_list = explode(";", $cmd_options['d']);
    $http_challenge_dir = $cmd_options['c'];
    $output_cert_file = $cmd_options['o'];
    $tos = isset($cmd_options['t']) ? $cmd_options['t'] : '';

    // load account key
    $key = loadAccountKey($account_key_file);
    if ($key === false) {
        return false;
    }

    // load csr file
    $csr = loadCsrFile($csr_file);
    if ($csr === false) {
        return false;
    }

    // register account
    if (registerAccount($key, $tos) === false) {
        return false;
    }

    // get thumb print
    $thumb_print = getThumbPrint($key);
    if ($thumb_print === false) {
        return false;
    }

    // domain challenge
    foreach ($domain_list as $domain) {
        if (domainChallenge($key, $domain,
                $http_challenge_dir, $thumb_print) === false) {
            return false;
        }
    }

    // issue cert
    if (issueCert($key, $csr, $output_cert_file) === false) {
        return false;
    }

    return true;
}

if (PHP_SAPI !== 'cli') {
    exit(1);
}
if (main($argc, $argv) === false) {
    exit(1);
}
exit(0);
