<?php

namespace DerrickSmith\HaloApi;

class HaloApi {
	private $grant_type;

	private $client_id;
	
	private $client_secret;
	
	private $scope;

	private $host;
	
	private $verifypeer;
	
	private $token_type;
	
	private $expires_in;

	private $access_token;
	
	private $refresh_token;
	
	public $last_result;


	public function __construct($arguments) {
		$arguments = func_get_args();

        if(!empty($arguments)){
            foreach($arguments[0] as $key => $property) {
				if(property_exists($this, $key)) {
                    $this->{$key} = $property;
				}
			}
		}
		
		$result = $this->initSession();
		
		$this->access_token = $result['data']->access_token;
		$this->refresh_token = $result['data']->refresh_token;
		$this->expires_in = $result['data']->expires_in;
		$this->token_type = $result['data']->token_type;
		$this->last_result = $result;
	}

    /**
     * PHP Rest CURL
     * https://github.com/jmoraleda/php-rest-curl
     * (c) 2014 Jordi Moraleda
     */

    private function exec($method, $endpoint, $obj = array()) {
        $curl = curl_init();
		
		$headers = array(
			($endpoint !== $this->host . '/auth/token' ? 'Authorization: Bearer '.$this->access_token : null)
		);

        switch($method) {
            case 'GET':
                if(!empty($obj)) {
                    $endpoint .= "?".http_build_query($obj);
                }
                break;

            case 'POST':
				if(!empty($obj)) {
					curl_setopt($curl, CURLOPT_POST, TRUE);
					if ($endpoint == $this->host . '/auth/token'){
						$headers[] = 'Content-Type: application/x-www-form-urlencoded';
						curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($obj));
					} else {
						$headers[] = 'Content-Type: application/json';
						curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($obj));
					}
				}
                break;

            case 'PUT':
            case 'DELETE':
            default:
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, strtoupper($method)); // method
                curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($obj)); // body
        }

        if($endpoint !== $this->host . '/auth/token' && $this->access_token == ''){
            throw new Exception("Failed: No Session Token");
			return false;
        }

        curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($curl, CURLOPT_URL, $endpoint);
        curl_setopt($curl, CURLOPT_HEADER, TRUE);
		curl_setopt($curl, CURLOPT_PORT , 443);
		#curl_setopt($curl, CURLOPT_VERBOSE, 1);



        if ($this->verifypeer === FALSE || $this->verifypeer == 0){
		    curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
		    curl_setopt ($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        } else {
            curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, TRUE);
        }
        // Exec
        $response = curl_exec($curl);
		
		if ($endpoint !== $this->host . '/auth/token'){
			echo $endpoint;
			echo "\n";
			print_r($response);
		}
		
        $info = curl_getinfo($curl);
		
        curl_close($curl);

        // Data
        $header = trim(substr($response, 0, $info['header_size']));
        $body = substr($response, $info['header_size']);
		$this->last_result = json_decode($body);
		
        return array('status' => $info['http_code'], 'header' => $header, 'data' => json_decode($body));
    }

    private function get($url, $obj = array()) {
        return $this->exec("GET", $url, $obj);
    }

    private function post($url, $obj = array()) {
        return $this->exec("POST", $url, $obj);
    }

    private function put($url, $obj = array()) {
        return $this->exec("PUT", $url, $obj);
    }

    private function delete($url, $obj = array()) {
        return $this->exec("DELETE", $url, $obj);
    }

	private function initSession() {
		$endpoint = $this->host . '/auth/token';
		$obj = array(
			'client_id' => $this->client_id,
			'client_secret' => $this->client_secret,
			'grant_type' => $this->grant_type,
			'scope' => $this->scope
		);
        return $this->post($endpoint, $obj);
	}
	
	//Actions

	public function getActions($obj = array()) {
		$endpoint = $this->host . '/api/actions';
        return $this->get($endpoint, $obj);
	}
	
	public function getAction($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/api/actions';
        return $this->get($endpoint, $obj);
	}
	
	public function postActions($obj = array()) {
		$endpoint = $this->host . '/api/actions';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteActions($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/api/actions/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Actions
	
	//Agents
	
	public function getAgents($obj = array()) {
		$endpoint = $this->host . '/Agent';
        return $this->get($endpoint, $obj);
	}
	
	public function getAgent($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Agent/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function getAgentSelf() {
		$endpoint = $this->host . '/Agent/me';
        return $this->get($endpoint, $obj);
	}
	
	public function postAgent($obj = array()) {
		$endpoint = $this->host . '/Agent';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteAgent($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Agent/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Agents
	
	//Appointments
	
	public function getAppointments($obj = array()) {
		$endpoint = $this->host . '/Appointment';
        return $this->get($endpoint, $obj);
	}
	
	public function getAppointment($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Appointment/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postAppointment($obj = array()) {
		$endpoint = $this->host . '/Appointment';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteAppointment($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Appointment/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Appointments
	
	//Assets
	
	public function getAssets($obj = array()) {
		$endpoint = $this->host . '/Asset';
        return $this->get($endpoint, $obj);
	}
	
	public function getAsset($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Asset/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postAsset($obj = array()) {
		$endpoint = $this->host . '/Asset';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteAsset($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Asset/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Assets
	
	//Attachments
	
	public function getAttachments($obj = array()) {
		$endpoint = $this->host . '/Attachment';
        return $this->get($endpoint, $obj);
	}
	
	public function getAttachment($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Attachment/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postAttachment($obj = array()) {
		$endpoint = $this->host . '/Attachment';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteAttachment($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Attachment/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Attachments
	
	//Clients
	
	public function getClients($obj = array()) {
		$endpoint = $this->host . '/Client';
        return $this->get($endpoint, $obj);
	}
	
	public function getClient($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Client/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postClient($obj = array()) {
		$endpoint = $this->host . '/Client';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteClient($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Client/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Clients
	
	//Contracts
	
	public function getContracts($obj = array()) {
		$endpoint = $this->host . '/Contract';
        return $this->get($endpoint, $obj);
	}
	
	public function getContract($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Contract/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postContract($obj = array()) {
		$endpoint = $this->host . '/Contract';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteContract($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Contract/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Contracts
	
	//Invoices
	
	public function getInvoices($obj = array()) {
		$endpoint = $this->host . '/Contract';
        return $this->get($endpoint, $obj);
	}
	
	public function getInvoice($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Invoice/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postInvoice($obj = array()) {
		$endpoint = $this->host . '/Invoice';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteInvoice($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Invoice/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Invoices
	
	//Items
	
	public function getItems($obj = array()) {
		$endpoint = $this->host . '/Item';
        return $this->get($endpoint, $obj);
	}
	
	public function getItem($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Item/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postItem($obj = array()) {
		$endpoint = $this->host . '/Item';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteItem($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Item/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Items
	
	//Kb Articles
	
	public function getKbArticles($obj = array()) {
		$endpoint = $this->host . '/KBArticle';
        return $this->get($endpoint, $obj);
	}
	
	public function getKbArticle($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/KBArticle/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postKbArticle($obj = array()) {
		$endpoint = $this->host . '/KBArticle';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteKbArticle($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/KBArticle/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Kb Articles
	
	//Opportunities
	
	public function getOpportunities($obj = array()) {
		$endpoint = $this->host . '/Opportunities';
        return $this->get($endpoint, $obj);
	}
	
	public function getOpportunity($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Opportunities/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postOpportunity($obj = array()) {
		$endpoint = $this->host . '/Opportunities';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteOpportunity($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Opportunities/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Opportunities
	
	//Projects
	
	public function getProjects($obj = array()) {
		$endpoint = $this->host . '/Projects';
        return $this->get($endpoint, $obj);
	}
	
	public function getProject($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Projects/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postProject($obj = array()) {
		$endpoint = $this->host . '/Projects';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteProject($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Projects/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Projects
	
	//Quotes
	
	public function getQuotes($obj = array()) {
		$endpoint = $this->host . '/Quotation';
        return $this->get($endpoint, $obj);
	}
	
	public function getQuote($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Quotation/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postQuote($obj = array()) {
		$endpoint = $this->host . '/Quotation';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteQuote($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Quotation/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Quotes
	
	//Reports
	
	public function getReports($obj = array()) {
		$endpoint = $this->host . '/Report';
        return $this->get($endpoint, $obj);
	}
	
	public function getReport($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Report/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postReport($obj = array()) {
		$endpoint = $this->host . '/Report';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteReport($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Report/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Reports
	
	//Sites
	
	public function getSites($obj = array()) {
		$endpoint = $this->host . '/Site';
        return $this->get($endpoint, $obj);
	}
	
	public function getSite($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Site/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postSite($obj = array()) {
		$endpoint = $this->host . '/Site';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteSite($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Site/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Sites
	
	//Statuses
	
	public function getStatuses($obj = array()) {
		$endpoint = $this->host . '/Status';
        return $this->get($endpoint, $obj);
	}
	
	public function getStatus($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Status/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postStatus($obj = array()) {
		$endpoint = $this->host . '/Status';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteStatus($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Status/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Statuses
	
	//Suppliers
	
	public function getSuppliers($obj = array()) {
		$endpoint = $this->host . '/Supplier';
        return $this->get($endpoint, $obj);
	}
	
	public function getSupplier($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Supplier/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postSupplier($obj = array()) {
		$endpoint = $this->host . '/Supplier';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteSupplier($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Supplier/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Suppliers
	
	//Teams
	
	public function getTeams($obj = array()) {
		$endpoint = $this->host . '/Team';
        return $this->get($endpoint, $obj);
	}
	
	public function getTeam($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Team/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postTeam($obj = array()) {
		$endpoint = $this->host . '/Team';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteTeam($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Team/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Teams
	
	//Ticket Types
	
	public function getTicketTypes($obj = array()) {
		$endpoint = $this->host . '/TicketType';
        return $this->get($endpoint, $obj);
	}
	
	public function getTicketType($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/TicketType/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postTicketType($obj = array()) {
		$endpoint = $this->host . '/TicketType';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteTicketType($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/TicketType/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Ticket Types
	
	//Tickets
	
	public function getTickets($obj = array()) {
		$endpoint = $this->host . '/api/Tickets';
        return $this->get($endpoint, $obj);
	}
	
	public function getTicket($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/api/Tickets/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postTicket($obj = array()) {
		$endpoint = $this->host . '/api/Tickets';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteTicket($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/api/Tickets/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Tickets
	
	//Users
	
	public function getUsers($obj = array()) {
		$endpoint = $this->host . '/Users';
        return $this->get($endpoint, $obj);
	}
	
	public function getUser($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Users/'.$obj['id'];
        unset($obj['id']);
		return $this->get($endpoint, $obj);
	}
	
	public function postUser($obj = array()) {
		$endpoint = $this->host . '/Users';
		return $this->post($endpoint, $obj);
	}
	
	public function deleteUser($obj = array()) {
		if(!isset($obj['id']) || empty($obj['id'])){
			throw new Exception("Missing 'id' parameter.");
			return false;
		}
		$endpoint = $this->host . '/Users/'.$obj['id'];
        unset($obj['id']);
		return $this->delete($endpoint, $obj);
	}
	
	//End Users
}

