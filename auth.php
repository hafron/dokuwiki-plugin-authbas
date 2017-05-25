<?php
// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();


class auth_plugin_authbas extends DokuWiki_Auth_Plugin {
	
	private $token='';
	
	private $bas_server = 'http://localhost/ghi/bas/';
	
	private function buildToken($user, $pass) {
		return $user . ':' . $pass;
	}

    public function __construct() {
        parent::__construct();
        
		$this->cando['addUser']   = true;
		$this->cando['delUser']   = true;
		$this->cando['modLogin']  = true;
		$this->cando['modPass']   = true;
		$this->cando['modName']   = true;
		$this->cando['modMail']   = true;
		$this->cando['modGroups'] = true;
		$this->cando['getUsers']     = true;
		$this->cando['getUserCount'] = true;
		
		$this->cando['logout'] = true;
		
		$this->success = true;
		
		if (isset($_SESSION[DOKU_COOKIE]['auth']['token'])) {
			$this->token = $_SESSION[DOKU_COOKIE]['auth']['token'];
		}
    }

    /**
     * Check user+password
     *
     * Checks if the given user exists and the given
     * plaintext password is correct
     *
     * @param string $user
     * @param string $pass
     * @return  bool
     */
    public function checkPass($user, $pass) {
		$this->user = $user;
		$this->pass = $pass;
		
		$this->token = $this->buildToken($user, $pass);
		$result = $this->getUserData($user);

        if ($result !== false) {
			$_SESSION[DOKU_COOKIE]['auth']['token'] = $this->token;
			return true;
		}
		return false;
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param string $user
     * @param bool $requireGroups  (optional) ignored by this plugin, grps info always supplied
     * @return array('name' => String, 'mail' => String, 'grps' => Array)|false
     */
    public function getUserData($user, $requireGroups=true) {
		
		$result = $this->_callAPI('GET', array('users', $user));
		
		if (isset($result['error'])) {
			return false;
		}

		return $result;
    }
    
	/**
     * Return a count of the number of user which meet $filter criteria
     *
     *
     * @param array $filter
     * @return int
     */
    public function getUserCount($filter = array()) {
        $result = $this->_callAPI('GET', array('users'),
									array_merge($filter, array('metaonly' => true)));
						
		
		return $result['meta']['count'];
    }
    
	/**
     * Bulk retrieval of user data
     *
     *
     * @param   int   $start index of first user to be returned
     * @param   int   $limit max number of users to be returned
     * @param   array $filter array of field/pattern pairs
     * @return  array userinfo (refer getUserData for internal userinfo details)
     */
    public function retrieveUsers($start = 0, $limit = 0, $filter = array()) {
		$result = $this->_callAPI('GET', array('users'),
			array_merge($filter, array('start' => $start, 'limit' => $limit)));
			
		
		return $result['data'];
    }
    
	/**
     * Create a new User
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     *
     * @param string $user
     * @param string $pwd
     * @param string $name
     * @param string $mail
     * @param array  $grps
     * @return bool|null|string
     */
    public function createUser($user, $pwd, $name, $mail, $grps = null) {
        //$pass = auth_cryptPassword($pwd);
        $pass = $pwd;

        // set default group if no groups specified
        if(!is_array($grps)) $grps = array($conf['defaultgroup']);

        $result = $this->_callAPI('POST', array('users'),
						array('user' => $user,
							  'pass' => $pass,
							  'name' => $name,
							  'mail' => $mail, 
							  'grps' => $grps));
		
		//Integrity constraint violation: 19 column user is not unique
		if (isset($result['error']) && $result['code'] === '23000') {
			 msg($this->getLang('userexists'), -1);
			 return false;
		} else if (isset($result['success'])) {
			return true;
		}
    }
    
    /**
     * Modify user data
     *
     * @author  Chris Smith <chris@jalakai.co.uk>
     * @param   string $user      nick of the user to be changed
     * @param   array  $changes   array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    public function modifyUser($user, $changes) {
        if (!is_array($changes) || count($changes) === 0) {
			return true;
		}

		
		if (isset($changes['pass'])) {
			//$changes['pass'] = auth_cryptPassword($changes['pass']);
			$changes['pass'] = $changes['pass'];
		}
		
		//it may change user name
		$result = $this->_callAPI('PUT', array('users', $user), $changes);
		
		//Integrity constraint violation: 19 column user is not unique
		if (isset($result['error']) && $result['code'] === '23000') {
			 msg($this->getLang('userexists'), -1);
			 return false;
		} else if (isset($result['error']) && $result['error'] === 'update user: user protected') {
			msg(sprintf($this->getLang('protected'), hsc($user)), -1);
			return false;
		} else if (isset($result['success'])) {
			return true;
		}

        return false;
    }

    /**
     * Remove one or more users from the list of registered users
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     */
    public function deleteUsers($users) {

        if(!is_array($users) || empty($users)) return 0;

        $deleted = array();

        foreach($users as $user) {
            if(isset($this->users[$user])) $deleted[] = preg_quote($user, '/');

			$result = $this->_callAPI('DELETE', array('users', $user));
			if (isset($result['error'])
				&& $result['error'] === 'delete user: user protected') {
				msg(sprintf($this->getLang('protected'), hsc($user)), -1);
			} else if (isset($result['success'])) {
				$deleted[] = $user;
			} else if (isset($result['error'])) {
				msg($result['error'], -1);
			}
        }
        
        return count($deleted);
    }
       
    // Method: POST, PUT, GET etc
	// Data: array("param" => "value") ==> index.php?param=value
	protected function _callAPI($method, $url_data=array(), $user_data = array())
	{
		$curl = curl_init();

		$data = array_merge(array('token' => $this->token), $user_data);

		$url = $this->bas_server.implode('/', $url_data);
		switch ($method) {
		case "POST":
			curl_setopt($curl, CURLOPT_POST, true);
			curl_setopt($curl, CURLOPT_POSTFIELDS,  http_build_query($data, '', '&'));
			break;
		case "PUT":
			//~ curl_setopt($curl, CURLOPT_PUT, true);
			curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
			curl_setopt($curl, CURLOPT_POSTFIELDS,  http_build_query($data, '', '&'));
			break;
		case "GET":
			$url = sprintf("%s?%s", $url, http_build_query($data, '', '&'));
			break;
		case "DELETE":
			curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
			$url = sprintf("%s?%s", $url, http_build_query($data, '', '&'));
			break;
		}

		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

		$result = curl_exec($curl);
		curl_close($curl);
		
		$pres = json_decode($result, true);
		
		if ($pres === NULL) {
			throw new Exception('Invalid json: '.$result);
		}
		
		return $pres;
	}
}
