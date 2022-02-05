<?php

namespace opnsensephp;

class Client {
    /**
     * URL of the OPNsense instance
     * e.g. 'https://10.0.0.1'
     * 
     * @var string
     */
    private $uri = "";

    /** 
    * API key for connection to OPNsense
    *
    * @var string
    */
    private $apiKey = "";

    /** 
    * API secret for connection to OPNsense
    *
    * @var string
    */
    private $apiSecret = "";

    /**
     * Allow insecure connections?
     * 
     * @var bool
     */
    private $insecure = false;

    /**
     * Initialise with necessary connection info
     * 
     * @param array $options
     */
    public function __construct($options = []) {
        $this->uri = $options['uri'];
        $this->apiKey = $options['apiKey'];
        $this->apiSecret = $options['apiSecret'];
        $this->insecure = (bool) $options['insecure'];
    }

    /**
     * Return if were validating SSL or not
     * 
     * @return bool
     */
    public function getInsecure() {
        return $this->insecure;
    }

    /**
     * Tell the app to accept secure connections or not
     * 
     * @param $value
     */
    public function setInsecure($value) {
        $this->insecure = (bool) $value;
    }

    /**
     * Generates the HTTP authorization header
     * 
     * @return string
     */
    private function generate_auth_header() {
        $auth = base64_encode($this->apiKey.':'.$this->apiSecret);
        return "Authorization: Basic $auth";
    }

    /**
     * Makes request to the OPNsense API
     * 
     * @param string $method
     * @param string $module
     * @param string $controller
     * @param string $command
     * @param array $params
     * @param string|int|array $data
     */
    private function opnsense_request($method, $module, $controller, $command, $params = [], $data = null) {
        $auth = $this->generate_auth_header();
        
        $opts = array(
            'http' => array(
                'method' => $method,
                'ignore_errors' => true,
                'header' => "${auth}\r\n",
            ),
        );

        if($method == 'POST') {
            $opts['http']['content'] = (empty($data))? null : json_encode($data);
            $opts['http']['header'] = "${auth}\r\nContent-Type: application/json\r\n";
        }

        if($this->insecure) {
            $opts['ssl']['verify_peer'] = false;
            $opts['ssl']['verify_peer_name'] = false;
            $opts['ssl']['allow_self_signed'] = true;
            $opts['ssl']['verify_host'] = false;
        }

        $context = stream_context_create($opts);
        $fp = fopen($this->uri.'/api/'.$module.'/'.$controller.'/'.$command.'/'.implode("/", $params), 'r', false, $context);
        $response  = stream_get_contents($fp);
        fclose($fp);

        $response = json_decode($response, true);
        return $response;
    }
    
    /**
     * Get list of all current Captive Portal sessions
     * 
     * @return array
     */
    public function captive_session_list($zone = 0) {
        return $this->opnsense_request('GET', 'captiveportal', 'session', 'list', array($zone));
    }

    /**
     * Add a user session to the Captive Portal
     * 
     * @param string $user
     * @param string $ip
     * @param integer $zone
     */
    public function captive_add_session($user, $ip, $zone = 0) {
        return $this->opnsense_request('POST', 'captiveportal', 'session', 'connect', array($zone), array('user' => $user, 'ip' => $ip));
    }

    /**
     * Search for an IP session in the Captive Portal
     * 
     * @param string $ip
     * 
     * @return bool
     */
    public function captive_session_search($ip) {
        $sessionList = $this->captive_session_list();
        $user = '';

        foreach($sessionList as $session) {
            if(isset($session['ipAddress']) && $session['ipAddress'] == $ip) {
                $user = $ip;
            }
        }

        if($user) {
            return true;
        } else {
            return false;
        }
    }
}