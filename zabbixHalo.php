<?php
// load Libraries
ini_set('register_argc_argv', TRUE);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


include(getcwd().'/vendor/autoload.php');
require_once 'lib/HaloApi.class.php';
require_once 'lib/ZabbixApi.class.php';

use Twig\Environment;
use IntelliTrend\Zabbix\ZabbixApi;
use derricksmith\HaloApi\HaloApi;

header("Content-Type: application/json");

/** 
* ZabbixHalo
* 
* ZabbixHalo is a class for creating Halo incidents from Zabbix alerts 
* 
* Example class usage: 
* 	$zabbixHalo = new ZabbixHalo($params);
*
* 
* @package ZabbixHalo 
* @author Derrick Smith
* @version $Revision: 1.0 $ 
* @access public 
* @see http://www.github.com/derricksmith/zabbixhalo 
*/


class ZabbixHalo {
	
    const VERSION 		= 'v1.0';
    const MASKDATETIME	= 'Y-m-d H:i:s';
    const MAXGRAPHS		= 4;
	
	private $CRLF;
	private $haloClientId;
	private $haloClientSecret;
	private $haloGrantType;
	private $haloScope;
	private $haloHost;
	private $haloCustomFieldId;
	private $haloCustomFieldName;
	private $haloTicketTypeId;
	private $haloTicketPriorityId;
	private $haloTicketClientId;
	private $haloTicketTeam;
	private $haloTicketCategory1;
	private $haloTicketUsername;
	private $zabbixUser;
	private $zabbixPassword;
	private $zabbixApiUser;
	private $zabbixApiPassword;
	private $zabbixUrlBase;
	private $zabbixUrlMedia;
	private $verifyPeer;
	private $httpProxy;
	private $loggingLevel;
	private $summary;
	private $duration;
	private $eventId;
	private $eventValue;
	private $itemId;
	private $graphMatch;
	private $graphHeight;
	private $graphWidth;
	private $period;
	private $periodHeader;
	private $showLegend;
	private $source;
	private $test;
	
	
	
	
	private $data;
	private $errors;
	
	/** 
	* Manages HaloITSM incidents from Zabbix input
	* 
	* @param array $params = [
	* 		'haloClientId' => '<CLIENT ID STRING>', 
	*		'haloClientSecret' => '<CLIENT SECRET STRING>', 
	*		'haloGrantType' => 'client_credentials',
	*		'haloScope' => 'all', 
	*		'haloHost' => 'https://<YOUR HALOITSM API URL>',
	*		'haloCustomFieldId' => 'Custom Field ID in Halo for Tracking Zabbix Event ID',
	*		'haloCustomFieldName' => 'Custom Field Name in Halo for Tracking Zabbix Event ID',
	*		'haloTicketTypeId' => '',
	*		'haloTicketPriorityId' => '',
	*		'haloTicketClientId' => '',
	*		'haloTicketTeam' => '',
	*		'haloTicketCategory1' => '',
	*		'haloTicketUsername' => '',
	*		'zabbixUser' => '',
	*		'zabbixPassword' => '',
	*		'zabbixApiUser' => '',
	*		'zabbixApiPassword' => '',
	*		'zabbixUrlBase => 'zabbix server base url',
	*		'zabbixUrlMedia => 'url location of this script',
	*		'verifyPeer' => 1, ----- SETS curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, TRUE)
	*		'httpProxy' => '',
	*		'loggingLevel' => 1, ----- 0=none,1=errors only,2=errors and warnings,3=info,4=debug
	*		'summary' => "{{ HOST_NAME|raw }}:  ({{ EVENT_SEVERITY }}) {{ EVENT_NAME|raw }}",
	*		'duration' => "{EVENT.DURATION}",
	*		'eventId' => "{EVENT.ID}",
	*		'eventValue' => "0",
	*		'itemId' => "{ITEM.ID}",
	*		'graphMatch' => "exact",
	*		'graphHeight' => "120",
	*		'graphWidth' => "300",
	*		'period' => "48h",
	*		'periodHeader' => "Last 48 Hours",
	*		'showLegend' => 0,
	*		'test' => 1,
	*		'source' => 'webhook'
	*	]
	* @return array 
	* @access public 
	*/
	function __construct($params){

		$this->logging("Calling ZabbixHalo", "INFO");
		
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Initialize Variables /////////////////////////////////////////////////////////////////////////////////
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		$this->CRLF = chr(10).chr(13);
		
		if (!isset($params) || (
			!isset($params['haloClientId']) ||
			!isset($params['haloClientSecret']) ||
			!isset($params['haloGrantType']) ||
			!isset($params['haloScope']) ||
			!isset($params['haloHost']) ||
			!isset($params['haloCustomFieldId']) ||
			!isset($params['haloCustomFieldName']) ||
			!isset($params['zabbixUser']) ||
			!isset($params['zabbixPassword']) ||
			!isset($params['zabbixApiUser']) ||
			!isset($params['zabbixApiPassword']) ||
			!isset($params['zabbixUrlBase']) ||
			!isset($params['zabbixUrlMedia']) ||
			!isset($params['duration']) ||
			!isset($params['eventId']) ||
			!isset($params['itemId']) ||
			!isset($params['source'])
		)) {
			$error = "Missing required configuration parameters.  Please supply all required parameters.  Params =".json_encode($params);
			$this->logging($error, "ERROR", true);
		}
		
		if (!isset($params['verifyPeer']) || empty($params['verifyPeer'])) $params['verifyPeer'] = 1;
		if (!isset($params['loggingLevel']) || empty($params['loggingLevel'])) $params['loggingLevel'] = 1;
		if (!isset($params['criticalPriority']) || empty($params['criticalPriority'])) $params['criticalPriority'] = 5;
		if (!isset($params['warningPriority']) || empty($params['warningPriority'])) $params['warningPriority'] = 3;
		if (!isset($params['summary']) || empty($params['summary'])) $params['summary'] = '{{ EVENT_SEVERITY }}: {{ EVENT_NAME|raw }}';
		if (!isset($params['graphMatch']) || empty($params['graphMatch'])) $params['graphMatch'] = 'any';
		if (!isset($params['graphHeight']) || empty($params['graphHeight'])) $params['graphHeight'] = 120;
		if (!isset($params['graphWidth']) || empty($params['graphWidth'])) $params['graphWidth'] = 450;
		if (!isset($params['period']) || empty($params['period'])) $params['period'] = '48h';
		if (!isset($params['periodHeader']) || empty($params['periodHeader'])) $params['periodHeader'] = '';
		if (!isset($params['showLegend']) || empty($params['showLegend'])) $params['showLegend'] = 0;
		if (!isset($params['test']) || empty($params['test'])) $params['test'] = 0;
		
		extract($params);
		
		$this->setVariable('haloClientId', $haloClientId);
		$this->setVariable('haloClientSecret', $haloClientSecret);
		$this->setVariable('haloGrantType', $haloGrantType);
		$this->setVariable('haloScope', $haloScope);
		$this->setVariable('haloHost', $haloHost);
		$this->setVariable('haloCustomFieldId', $haloCustomFieldId);
		$this->setVariable('haloCustomFieldName', $haloCustomFieldName);
		$this->setVariable('haloTicketTypeId', $haloTicketTypeId);
		$this->setVariable('haloTicketPriorityId', $haloTicketPriorityId);
		$this->setVariable('haloTicketClientId', $haloTicketClientId);
		$this->setVariable('haloTicketTeam', $haloTicketTeam);
		$this->setVariable('haloTicketCategory1', $haloTicketCategory1);
		$this->setVariable('haloTicketUsername', $haloTicketUsername);
		$this->setVariable('zabbixUser', $zabbixUser);
		$this->setVariable('zabbixPassword', $zabbixPassword, true);  //mask password in log file
		$this->setVariable('zabbixApiUser', $zabbixApiUser);
		$this->setVariable('zabbixApiPassword', $zabbixApiPassword, true);  //mask password in log file
		$this->setVariable('zabbixUrlBase', $zabbixUrlBase);
		$this->setVariable('zabbixUrlApi', $zabbixUrlBase.'/api_jsonrpc.php');
		$this->setVariable('zabbixUrlMedia', $zabbixUrlMedia);
		$this->setVariable('zabbixUrlMediaImage', $zabbixUrlMedia.'/images/');
		$this->setVariable('zabbixMediaPath', getcwd().'/');
		$this->setVariable('zabbixMediaPathImage', $this->zabbixMediaPath.'images/');
		$this->setVariable('zabbixMediaPathTemplate', $this->zabbixMediaPath.'templates/');
		$this->setVariable('zabbixMediaPathCookies', $this->zabbixMediaPath.'tmp/');
		$this->setVariable('zabbixMediaPathLog', $this->zabbixMediaPath.'log/');
		$this->setVariable('verifyPeer', $verifyPeer);
		$this->setVariable('httpProxy', $httpProxy);
		$this->setVariable('loggingLevel', $loggingLevel);
		$this->setVariable('summary', $summary);
		$this->setVariable('duration', $duration);
		$this->setVariable('eventId', $eventId);
		$this->setVariable('eventValue', $eventValue);
		$this->setVariable('itemId', $itemId);
		$this->setVariable('graphMatch', $graphMatch);
		$this->setVariable('graphHeight', $graphHeight);
		$this->setVariable('graphWidth', $graphWidth);
		$this->setVariable('period', $period);
		$this->setVariable('periodHeader', $periodHeader);
		$this->setVariable('showLegend', $showLegend);	
		$this->setVariable('test', $test);
		$this->setVariable('source', $source);
		
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Sanity Checks ////////////////////////////////////////////////////////////////////////////////////////
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		// Check curl extension is installed
		if (!extension_loaded("curl")) {
			$this->logging(_("Extension curl not loaded"), "ERROR", true);
		}

		// Check directories are writable
		if (!is_writable($this->zabbixMediaPathImage)) $this->logging(_("Image path inaccessible"), "ERROR", true);
		if (!is_writable($this->zabbixMediaPathCookies)) $this->logging(_("Cookies temporary path inaccessible"), "ERROR", true);
		if (!is_writable($this->zabbixMediaPathLog)) $this->logging(_("Log path inaccessible"), "ERROR", true); 
		if (!file_exists($this->zabbixMediaPathTemplate.'html.template')) $this->logging(_("HTML template missing"), "ERROR", true);
		if (!file_exists($this->zabbixMediaPathTemplate.'plain.template')) $this->logging(_("PLAIN template missing"), "ERROR", true);
		
		
		
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Zabbix Process ///////////////////////////////////////////////////////////////////////////////////////
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		$this->data = array();
		$this->data['BASE_URL'] = $this->zabbixUrlBase;
		$this->data['SUBJECT'] = $this->summary;
		
		// Get Zabbix Auth Token
		$this->logging("Getting auth token from Zabbix", "INFO");
		$zbx = new ZabbixApi();
		try {
			$zbx->login($this->zabbixUrlApi, $this->zabbixApiUser, $this->zabbixApiPassword);	
		} catch (Exception $e) {
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		// Get Zabbix Event Data
		$this->logging("Getting event data from Zabbix", "INFO");
		try {
			$thisEvent = $zbx->call('event.get', array(
				"eventids" => $this->eventId, 
				"output" => "extend", 
				"selectRelatedObject" => "extend", 
				"selectSuppressionData" => "extend"
			));
			
			// Die if no response data
			if (!isset($thisEvent[0])) $this->logging('No event data received', "ERROR", true); 
			
			$this->logging('EventData: '.json_encode($thisEvent,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
			
			$this->data['EVENT_ID'] = $thisEvent[0]['eventid'];
			$this->data['EVENT_NAME'] = $thisEvent[0]['name'];
			$this->data['EVENT_OPDATA'] = $thisEvent[0]['opdata'];
			$this->data['EVENT_SUPPRESSED'] = $thisEvent[0]['suppressed'];
			$this->data['EVENT_VALUE'] = $thisEvent[0]['relatedObject']['value'];
			
			//Override EVENT_VALUE for testing
			if (isset($this->eventValue) && (
				($this->eventValue == 0 || $this->eventValue == false) 
				|| ($this->eventValue == 1 || $this->eventValue == true)
			)) {
				switch($this->eventValue){
					case 0:
						$this->data['EVENT_VALUE'] = $this->eventValue;
						break;
						
					case 1:
						$this->data['EVENT_VALUE'] = $this->eventValue;
						break;
				}
			}

			switch($this->data['EVENT_VALUE']){
				case 0: // Recovering
						$this->data['EVENT_SEVERITY'] = 'Resolved';
						$this->data['EVENT_STATUS'] = 'Recovered';
						break;

				case 1: // Triggered/Active
						$_severity = array('Not classified','Information','Warning','Average','High','Disaster');
						$this->data['EVENT_SEVERITY'] = $_severity[$thisEvent[0]['severity']];
						$this->data['EVENT_STATUS'] = 'Triggered/Active';
						break;
			}

			$triggerId = $thisEvent[0]['relatedObject']['triggerid'];
			
		} catch (Exception $e) {
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		// Get Zabbix Trigger Data
		$this->logging("Getting trigger data from Zabbix", "INFO");
		try {
			$thisTrigger = $zbx->call('trigger.get', array(
				"triggerids" => $triggerId, 
				"output" => "extend", 
				"selectFunctions" => "extend", 
				"selectTags" => "extend",
				"expandComment" => 1,
                "expandDescription" => 1,
                "expandExpression" => 1
			));
			
			// Die if no response data
			if (!isset($thisTrigger[0])) $this->logging('No trigger data received', "ERROR", true);
			
			$this->logging('TriggerData: '.json_encode($thisTrigger,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
			
			$this->data['TRIGGER_ID'] = $thisTrigger[0]['triggerid'];
			$this->data['TRIGGER_DESCRIPTION'] = $thisTrigger[0]['description'];
			$this->data['TRIGGER_COMMENTS'] = $thisTrigger[0]['comments'];
			
			$forceGraph = 0;
			$triggerScreen = 0;
			$triggerScreenPeriod = '';
			$triggerScreenPeriodHeader = '';

			foreach($thisTrigger[0]['tags'] as $aTag){
				echo $aTag;
				echo "\n";
				switch ($aTag['tag']){
					case 'mailGraph.period':
						$this->period = $aTag['value'];
						$this->logging('+ Graph display period override = '.$this->period, "INFO");
						break;

					case 'mailGraph.period_header':
						$this->periodHeader = $aTag['value'];
						$this->logging('+ Graph display period header override = '.$this->periodHeader, "INFO");
						break;

					case 'mailGraph.periods':
						$this->periods = $aTag['value'];
						$this->logging('+ Graph display periods override = '.$this->periods, "INFO");
						break;

					case 'mailGraph.periods_headers':
						$this->periodsHeaders = $aTag['value'];
						$this->logging('+ Graph display periods headers override = '.$this->periodsHeaders, "INFO");
						break;

					case 'mailGraph.graph':
						$forceGraph = intval($aTag['value']);
						_log('+ Graph ID to display = '.$forceGraph);
						$this->logging('+ Graph ID to display = '.$forceGraph, "INFO");
						break;

					case 'mailGraph.showLegend':
						$this->showLegend = intval($aTag['value']);
						_log('+ Graph display legend override = '.$this->showLegend);
						$this->logging('+ Graph display legend override = '.$this->showLegend, "INFO");
						break;

					case 'mailGraph.graphWidth':
						$this->graphWidth = intval($aTag['value']);
						$this->logging('+ Graph height override = '.$this->graphWidth, "INFO");
						break;

					case 'mailGraph.graphHeight':
						$this->graphHeight = intval($aTag['value']);
						$this->logging('+ Graph height override = '.$this->graphHeight, "INFO");
						break;

					case 'mailGraph.screen':
						$triggerScreen = intval($aTag['value']);
						$this->logging('+ Trigger screen = '.$triggerScreen, "INFO");
						break;

					case 'mailGraph.screenPeriod':
						$triggerScreenPeriod = $aTag['value'];
						$this->logging('+ Trigger screen period = '.$triggerScreenPeriod, "INFO");
						break;

					case 'mailGraph.screenPeriodHeader':
						$triggerScreenPeriodHeader = $aTag['value'];
						$this->logging('+ Trigger screen header = '.$triggerScreenPeriodHeader, "INFO");
						break;
				}
			}

			if (!isset($this->itemId))
			{
				foreach($thisTrigger['thisItem'][0]['functions'] as $aFunction)
				{
					$this->itemId = $aFunction['itemid'];
					$this->logging('- Item ID taken from trigger (first) function = '.$this->itemId, "INFO");
					break;
				}
			}
		} catch (Exception $e) {
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		//
		// Get Zabbix Item Data
		//
		$this->logging("Getting item data from Zabbix", "INFO");
		try {
			$thisItem = $zbx->call('item.get', array(
				"itemids" => $this->itemId, 
				"output" => "extend"
			));
			
			// Die if no response data
			if (!isset($thisItem[0])) $this->logging('No item data received', "ERROR", true);
			
			$this->logging('ItemData: '.json_encode($thisItem,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
			
			$this->data['ITEM_ID'] = $thisItem[0]['itemid'];
			$this->data['ITEM_KEY'] = $thisItem[0]['key_'];
			$this->data['ITEM_NAME'] = $thisItem[0]['name'];
			$this->data['ITEM_DESCRIPTION'] = $thisItem[0]['description'];
			$this->data['ITEM_LASTVALUE'] = $thisItem[0]['lastvalue'];
			$this->data['ITEM_PREVIOUSVALUE'] = $thisItem[0]['prevvalue'];

			// Catch elements that have a recordset definition returned as a value ...
			if (substr($this->data['ITEM_LASTVALUE'],0,5)=='<?xml') $this->data['ITEM_LASTVALUE'] = '[record]';
			if (substr($this->data['ITEM_PREVIOUSVALUE'],0,5)=='<?xml') $this->data['ITEM_PREVIOUSTVALUE'] = '[record]';

			// Catch long elements
			if (strlen($this->data['ITEM_LASTVALUE'])>50) $this->data['ITEM_LASTVALUE'] = substr($this->data['ITEM_LASTVALUE'],0,50).' ...';
			if (strlen($this->data['ITEM_PREVIOUSVALUE'])>50) $this->data['ITEM_PREVIOUSVALUE'] = substr($this->data['ITEM_PREVIOUSVALUE'],0,50).' ...';

			$hostId = $thisItem[0]['hostid'];
			
		} catch (Exception $e){
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		//
		// Get Zabbix Host Data
		//
		$this->logging("Getting host data from Zabbix", "INFO");
		try {
			$thisHost = $zbx->call('host.get', array(
				"hostids" => $hostId, 
				"output" => "extend",
				"selectTags" => "extend",
			));
			
			// Die if no response data
			if (!isset($thisHost[0])) $this->logging('No host data received', "ERROR", true);
			
			$this->logging('HostData: '.json_encode($thisHost,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
			
			$this->data['HOST_ID'] = $thisHost[0]['hostid'];
			$this->data['HOST_NAME'] = $thisHost[0]['name'];
			if (isset($thisHost[0]['error'])) $this->data['HOST_ERROR'] = $thisHost[0]['error'];
			$this->data['HOST_DESCRIPTION'] = $thisHost[0]['description'];

			// --- Custom settings?
			$hostScreen = 0;
			$hostScreenPeriod = '';
			$hostScreenPeriodHeader = '';

			foreach($thisHost[0]['tags'] as $aTag){
				switch ($aTag['tag']){
					case 'zabbixhalo.screen':
						$hostScreen = intval($aTag['value']);
						$this->logging('+ Host screen (from TAG) = '.$hostScreen, "INFO");
						break;

					case 'zabbixhalo.screenPeriod':
						$hostScreenPeriod = $aTag['value'];
						$this->logging('+ Host screen period (from TAG) = '.$hostScreenPeriod, "INFO");
						break;

					case 'zabbixhalo.screenPeriodHeader':
						$hostScreenPeriodHeader = $aTag['value'];
						$this->logging('+ Host screen period header (from TAG) = '.$hostScreenPeriodHeader, "INFO");
						break;
				}
			}
			
		} catch (Exception $e){
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		//
		// Get Zabbix Host Macro Data
		//
		$this->logging("Getting host macro data from Zabbix", "INFO");
		try {
			$thisHostMacro = $zbx->call('usermacro.get', array(
				"hostids" => $hostId, 
				"output" => "extend"
			));
			
			if (isset($thisHostMacro[0])) {
			
				$this->logging('HostMacroData: '.json_encode($thisHostMacro,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
				
				foreach($thisHostMacro as $aMacro){
					switch($aMacro['macro']){
						case 'zabbixhalo.screen':
							$hostScreen = intval($aMacro['value']);
							$this->logging('+ Host screen (from MACRO) = '.$hostScreen, "INFO");
							break;

						case 'zabbixhalo.screenPeriod':
							$hostScreenPeriod = $aMacro['value'];
							$this->logging('+ Host screen period (from MACRO) = '.$hostScreenPeriod, "INFO");
							break;

						case 'zabbixhalo.screenPeriodHeader':
							$hostScreenPeriodHeader = $aMacro['value'];
							$this->logging('+ Host screen header (from MACRO) = '.$hostScreenPeriodHeader, "INFO");
							break;
					}
				}
			} else {
				$this->logging('No host macro data received', "ERROR");
			}
			
		} catch (Exception $e){
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		//
		// Get Zabbix Graph Data
		//
		$this->logging("Getting graph data from Zabbix", "INFO");
		
		$searchItems = array();

		foreach($thisTrigger[0]['functions'] as $aFunction)
		{
			$searchItems[] = $aFunction['itemid'];
		}

		$keyName = $thisItem[0]['key_'];
		$hostId = $thisItem[0]['hostid'];
		
		try {
			$thisGraphs = $zbx->call('graph.get', array(
				"hostids" => $hostId, 
				"itemids" => $searchItems,
                "expandName" => 1,
                "selectGraphItems" => "extend",
                "output" => "extend"
			));
			
			print_r($thisGraphs);
			
			if (isset($thisGraphs[0])) {
				$this->logging('GraphData: '.json_encode($thisGraphs,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
			} else {
				$this->logging('No graph data received', "ERROR");
			}
			
		} catch (Exception $e) {
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}
		
		//
		// Get Graph associated with forcegraph
		//
		if ($forceGraph>0){
			
			$this->logging('# Retrieving FORCED graph information', "INFO");

			try {
				$forceGraphInfo = $zbx->call('graph.get', array(
					"graphids" => $forceGraph, 
					"expandName" => 1,
					"output" => "extend"
				));
				
				if (isset($forceGraphInfo[0])) {
					$this->logging('GraphData: '.json_encode($thisGraphs,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
				} else {
					$this->logging('! No data received for graph #'.$forceGraph.'; discarding forced graph information', "WARNING");
					$forceGraph = 0;
				}
				
			} catch (Exception $e) {
				$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
				$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
			}
		}
		
		//
		// Find Matching Graph Items for Trigger Items
		//
		$itemIds = array();

		foreach($thisTrigger[0]['functions'] as $aFunction)
		{
			$didFind = FALSE;

			foreach($itemIds as $anItem){
				if ($anItem==$aFunction['itemid']) $didFind = TRUE; break;
			}

			if (!$didFind) $itemIds[] = $aFunction['itemid'];
		}

		$matchedGraphs = array();
		$otherGraphs = array();

		foreach($thisGraphs as $aGraph){
			foreach($aGraph['gitems'] as $aGraphItem){
				foreach($itemIds as $anItemId){
					if ($aGraphItem['itemid']==$anItemId){
						if ($anItemId==$this->itemId){
							$this->logging('+ Graph #'.$aGraphItem['graphid'].' full match found (item #'.$aGraphItem['itemid'].')', "INFO");
							$matchedGraphs[] = $aGraph;
						} else {
							$otherGraphs[] = $aGraph;
							$this->logging('~ Graph #'.$aGraphItem['graphid'].' partial match found (item #'.$aGraphItem['itemid'].')', "INFO");
						}
					}
				}
			}
		}
		
		//
		// Find Matching Graph Items with Trigger and/or Host screen reference
		//
		$triggerGraphs = array();

		if ($triggerScreen>0){
			$this->logging('# Fetching graph information for TRIGGER for screen #'.$hostScreen, "INFO");
			$triggerGraphs = $this->fetchGraphsFromScreen($triggerScreen);
			$this->logging('> Graphs found = '.sizeof($triggerGraphs), "INFO");
		}

		$hostGraphs = array();

		if ($hostScreen>0){
			$this->logging('# Fetching graph information for HOST for screen #'.$hostScreen, "INFO");
			$hostGraphs = $this->fetchGraphsFromScreen($hostScreen);
			$this->logging('# Fetching graph information for HOST for screen #'.$hostScreen, "INFO");
		}
		

		//
		// // Determine number of periods for the ITEM graphs
		//
		$p_periods = array();
		$p_periods_headers = array();

		if (isset($this->data['periods'])){
			// Multiple periods mode selected
			$this->logging('# Multi period graph mode selected', "INFO");

			$p_periods = explode(',',$this->data['periods']);

			// If invalid, replace with single graph item
			if (sizeof($p_periods)==0) $p_periods[] = $this->period;

			// --- Determine headers
			if (isset($this->data['periodsHeaders'])) $p_periods_headers = explode(',',$this->data['periodsHeaders']);

			// If no headers specified, simply copy the period information
			if (sizeof($p_periods_headers)==0) $p_periods_headers = $p_periods;
		} else {
			// Single period mode selected
			$p_periods[] = $this->period;

			if (isset($this->data['periodHeader'])){
				$p_periods_headers[] = $this->data['periodHeader'];
			} else {
				$p_periods_headers[] = $this->period;
			}
		}

		// Strip off any excessive elements from the end

		while (sizeof($p_periods)>SELF::MAXGRAPHS) { array_pop($p_periods); }
		while (sizeof($p_periods_headers)>SELF::MAXGRAPHS) { array_pop($p_periods_headers); }

		// Fetching of the ITEM graphs

		$graphFiles = array();
		$graphURL = '';

		// If we have any matching graph, make the embedding information available

		if ((sizeof($matchedGraphs) + sizeof($otherGraphs) + $forceGraph)>0){
			if ($forceGraph>0){
				$theGraph = $forceGraphInfo;
				$theType = 'Forced';
			} else {
				if (sizeof($matchedGraphs)>0){
					$theGraph = $matchedGraphs[0];
					$theType = 'Matched';
				} else {
					if (sizeof($otherGraphs)>0){
						$theGraph = $otherGraphs[0];
						$theType = 'Other';
					}
				}
			}

			$this->data['GRAPH_ID'] = $theGraph['graphid'];
			$this->data['GRAPH_NAME'] = $theGraph['name'];
			$this->data['GRAPH_MATCH'] = $theType;

			$this->logging('# Adding '.strtoupper($theType).' graph #'.$this->data['GRAPH_ID'], "INFO");

			foreach($p_periods as $aKey=>$aPeriod){
				$graphFile = $this->GraphImageById($this->data['GRAPH_ID'],
											$this->graphWidth,$this->graphHeight,
											$theGraph['graphtype'],
											$this->showLegend,$aPeriod);

				$graphFiles[] = $graphFile;

				$this->data['GRAPHS_I'][$aKey]['PATH'] = $this->zabbixMediaPathImage . $graphFile;
				$this->data['GRAPHS_I'][$aKey]['URL'] = $this->zabbixUrlMediaImage . $graphFile;
				$this->data['GRAPHS_I'][$aKey]['HEADER'] = $p_periods_headers[$aKey];
			}

			$this->data['GRAPH_ZABBIXLINK'] = $this->zabbixUrlBase.'/graphs.php?form=update&graphid='.$this->data['GRAPH_ID'];
		}
		
		//
		// Fetch graphs associated to TRIGGER or HOST screen references obtained earlier
		//
		if (sizeof($triggerGraphs)>0){
			if ($triggerScreenPeriod==''){
				$triggerScreenPeriod = $p_periods[0];
				$triggerScreenPeriodHeader = $p_periods_headers[0];
			}

			if ($triggerScreenPeriodHeader=='') $triggerScreenPeriodHeader = $triggerScreenPeriod;

			$this->addGraphs('T',$triggerGraphs,$triggerScreenPeriod,$triggerScreenPeriodHeader);

			$this->data['TRIGGER_SCREEN'] = $triggerScreen;
		}

		if (sizeof($hostGraphs)>0){
			if ($hostScreenPeriod==''){
				$hostScreenPeriod = $p_periods[0];
				$hostScreenPeriodHeader = $p_periods_headers[0];
			}

			if ($hostScreenPeriodHeader=='') $hostScreenPeriodHeader = $hostScreenPeriod;

			$this->addGraphs('H',$hostGraphs,$hostScreenPeriod,$hostScreenPeriodHeader);

			$this->data['HOST_SCREEN'] = $hostScreen;
		}
		
		//
		//Finalize data array
		//
		$this->data['TRIGGER_URL'] = $this->zabbixUrlBase.'/triggers.php?form=update&triggerid='.$this->data['TRIGGER_ID'];
		$this->data['ITEM_URL'] = $this->zabbixUrlBase.'/items.php?form=update&hostid='.$this->data['HOST_ID'].'&itemid='.$this->data['ITEM_ID'];
		$this->data['HOST_URL'] = $this->zabbixUrlBase.'/hosts.php?form=update&hostid='.$this->data['HOST_ID'];
		$this->data['EVENTDETAILS_URL'] = $this->zabbixUrlBase.'/tr_events.php?triggerid='.$this->data['TRIGGER_ID'].'&eventid='.$this->data['EVENT_ID'];

		$this->data['EVENT_DURATION'] = $this->duration;
		
		//
		//Build Templates
		//
		$loader = new \Twig\Loader\ArrayLoader([
			'html' => file_get_contents($this->zabbixMediaPathTemplate.'html.template'),
			'plain' => file_get_contents($this->zabbixMediaPathTemplate.'plain.template'),
			'subject' => $this->data['SUBJECT'],
		]);

		$twig = new \Twig\Environment($loader);
		
		$this->embedGraphs($graphFiles,'I','ITEM');
		$this->embedGraphs($triggerGraphs,'T','TRIGGER');
		$this->embedGraphs($hostGraphs,'H','HOST');
		
		$haloDetailsHtml = $twig->render('html', $this->data);
		$haloDetailsPlain = $twig->render('plain', $this->data);
		$haloSummary = $twig->render('subject', $this->data);
		
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Halo Process ///////////////////////////////////////////////////////////////////////////////////////
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		// Only process halo incidents if not test
		if ($this->test == 0 || $this->test === false){
		
			//
			//Get Halo Access Token
			//
			$this->logging("Calling Halo API", "INFO");
			$halo = new HaloApi(array(
				'client_id' => $this->haloClientId, 
				'client_secret' => $this->haloClientSecret, 
				'grant_type' => $this->haloGrantType,
				'scope' => $this->haloScope,
				'host' => $this->haloHost, 
				'verifypeer' => $this->verifyPeer
			));	
				
			if (isset($halo->last_result['data']->access_token) && !empty($halo->last_result['data']->access_token)){
				$this->logging("Halo Session Token = ".$halo->last_result['data']->access_token, "INFO");
			} else {
				$this->logging("Halo API Unknown Error, Unable to retrieve token", "ERROR");
				die("Unable to obtain token");
			}
			
			switch($this->data['EVENT_VALUE']){
				case 0: // Recovering
					$this->logging("Event is recovering, updating Halo tickets", "INFO");
					
					$this->logging('Getting open tickets', "INFO");
					$request = array(
						'pageinate' => true,
						'page_size' => 50,
						'page_no' => 1,
						'columns_id' => 1,
						'includecolumns' => false,
						//'view_id' => 2,
						//'ticketarea_id' => 1,
						'ticketlinktype' => null,
						'searchactions' => null,
						'advanced_search' => '[{"filter_name":"cf_185","filter_type":4,"filter_value":"'.$this->data['EVENT_ID'].'"}]',
						'order' => 'id',

					);
					$tickets = $halo->getTickets($request);
					
					$this->logging('TicketData: '.json_encode($tickets,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
								
					$array = json_decode(json_encode($tickets['data']), true);
					$request = array();
					foreach($array['tickets'] as $ticket){
						$ticket_id = $ticket['id'];
						$request[] = array(
							'ticket_id' 		=> $ticket_id,
							'note_html' 		=> $haloDetailsHtml,
							'new_status'		=>	"9",
							'outcome_id'		=> "7",
							'hiddenfromuser' 	=> true,
						);
					}
					$this->logging('Posting ticket updates', "INFO");			
					$ticketUpdates = $halo->postActions($request);
					
					$this->logging('TicketUpdates: '.json_encode($ticketUpdates,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
					
					$return_status = 'success';
					
					break;

				case 1: // Triggered/Active
					$this->logging("Event is problem, creating new ticket in Halo", "INFO");
							
					$ticket = array(
						array(
							'summary' => $haloSummary,
							'details' => $haloDetailsHtml,
							'Customfields' => array(
								array(
									'name' 	=> $this->haloCustomFieldName,
									'value' => $this->data['EVENT_ID']
								)
							),
						)
					);
					
					if (isset($this->haloTicketPriorityId) && !empty($this->haloTicketPriorityId)) $ticket[0]['priority_id'] = $this->haloTicketPriorityId;
					if (isset($this->haloTicketTypeId) && !empty($this->haloTicketTypeId)) $ticket[0]['tickettype_id'] = $this->haloTicketTypeId;
					if (isset($this->haloTicketTeam) && !empty($this->haloTicketTeam)) $ticket[0]['team'] = $this->haloTicketTeam;
					if (isset($this->haloTicketClientId) && !empty($this->haloTicketClientId)) $ticket[0]['client_id'] = $this->haloTicketClientId;
					if (isset($this->haloTicketUsername) && !empty($this->haloTicketUsername)) $ticket[0]['user_name'] = $this->haloTicketUsername;
					if (isset($this->haloTicketCategory1) && !empty($this->haloTicketCategory1)) $ticket[0]['category_1'] = $this->haloTicketCategory1;
					
					try {
						$result = $halo->postTicket($ticket);
						$this->logging('TicketData: '.json_encode($result,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
						
						$return_status = 'success';
						
					} catch (Exception $e) {
						$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
						$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
					}
					break;
			}
		}

		
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// Clean Up /////////////////////////////////////////////////////////////////////////////////////////////
		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		
		//Remove Images
		foreach($this->images as $image){
			if(file_exists($image)){
				unlink($image);
				$this->logging('> Deleting image '.$image, "INFO");
			}else{
				$this->logging('> Unable to delete image '.$image, "INFO");
			}
		}
		
		//Return json 
		echo json_encode(array('errors' => $this->errors, 'status' => ($return_status == 'success' ? 'success' : 'failure') ));
		exit();
	}

	private static function _sort($a,$b){
        if ($a['screen']['y']>$b['screen']['y']) { return(1); }
        if ($a['screen']['y']<$b['screen']['y']) { return(-1); }
        if ($a['screen']['x']>$b['screen']['x']) { return(1); }
        if ($a['screen']['x']<$b['screen']['x']) { return(-1); }
        return(0);
    }

    private function fetchGraphsFromScreen($screenId) {
        // Pick up the SCREEN ITEMS associated to the SCREEN
		$this->logging('> Get Screen items data for screen #'.$screenId, "INFO");
		try {
			$screenGraphs = $zbx->call('screen.get', array(
				"screenids" => $screenId,
                "output" => "extend",
                "selectScreenItems" => "extend"
			));
				
			// Die if no response data
			if (!isset($screenGraphs[0])) $this->logging('No screen graphs data received', "ERROR", true);
				
			$this->logging('> Screen items data for screen #'.$screenId.$this->CRLF.json_encode($screenGraphs,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
				
		} catch (Exception $e) {
			$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
			$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
		}

        // --- Filter on specific type(s) and enrich the graph data

        $result = array();

        foreach($screenGraphs[0]['screenitems'] as $anItem)
        {
            switch($anItem['resourcetype'])
            {
                case 0: // Graph
                    $this->logging('> Get Graph for resource #'.$anItem['resourceid'], "INFO");
					try {
						$screenGraph = $zbx->call('graph.get', array(
							"graphids" => $anItem['resourceid'],
							"expandName" => 1,
							"output" => "extend"
						));
							
						// Die if no response data
						if (!isset($screenGraph[0])) $this->logging('No screen graph data received', "ERROR", true);
							
						$this->logging('+ Graph data for screen item #'.$anItem['screenitemid'].$this->CRLF.
							json_encode($screenGraph,JSON_PRETTY_PRINT|JSON_NUMERIC_CHECK), "INFO");
							
					} catch (Exception $e) {
						$this->logging('ErrorCode: '.$e->getCode(), "ERROR");
						$this->logging('ErrorMessage: '.$e->getMessage(), "ERROR", true);
					}

                    $result[] = array('screen'=>$anItem,'name'=>$screenGraphs[0]['name'],'graph'=>$screenGraph[0]);
                    break;
            }
        }

        // --- Sort the result according to SCREEN x,y position

        usort($result, array('ZabbixHalo','_sort'));

        // --- Done

        return($result);
    }
	
	private function GraphImageById ($graphid, $width = 400, $height = 100, $graphType = 0, $showLegend = 0, $period = '48h')
    {
        // Unique names
        $thisTime = time();

        // Relative web calls
        $z_url_index   = $this->zabbixUrlBase ."/index.php";

        switch($graphType)
        {
           // 0: Normal
           // 1: Stacked
           case 0:
           case 1:
                $z_url_graph   = $this->zabbixUrlBase ."/chart2.php";
                break;

           // 2: Pie
           // 3: Exploded
           case 2:
           case 3:
                $z_url_graph   = $this->zabbixUrlBase ."/chart6.php";
                break;

           default:
                // Catch all ...
                $this->logging('% Graph type #'.$graphType.' unknown; forcing "Normal"', "INFO");
                $z_url_graph   = $this->zabbixUrlBase ."/chart2.php";
        }

        $z_url_fetch   = $z_url_graph ."?graphid=" .$graphid ."&width=" .$width ."&height=" .$height .
                                       "&graphtype=".$graphType."&legend=".$showLegend."&profileIdx=web.graphs.filter".
                                       "&from=now-".$period."&to=now";

        // Prepare POST login
        $z_login_data  = array('name' => $this->zabbixUser, 'password' => $this->zabbixPassword, 'enter' => "Sign in");

        // Cookie and image names
        $filename_cookie = $this->zabbixMediaPathCookies ."zabbix_cookie_" .$graphid . "." .$thisTime. ".txt";
        $filename = "zabbix_graph_" .$graphid . "." . $thisTime . "-" . $period . ".png";
        $image_name = $this->zabbixMediaPathImage . $filename;

        // Configure CURL
        $this->logging('% GraphImageById: '.$z_url_fetch, "INFO");
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $z_url_index);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Zabbix-Halo - '.SELF::VERSION);

        if ((isset($this->HttpProxy)) && ($this->HttpProxy != ''))
        {
            $this->logging('% Using proxy: '.$this->HttpProxy, "INFO");
            curl_setopt($ch, CURLOPT_PROXY, $this->HttpProxy);
        }

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $z_login_data);

        curl_setopt($ch, CURLOPT_COOKIEJAR, $filename_cookie);
        curl_setopt($ch, CURLOPT_COOKIEFILE, $filename_cookie);

        // Login to Zabbix
        $login = curl_exec($ch);

        if ($login!='')
        {
			$error = 'Error logging in to Zabbix!'.$this->CRLF;
			$this->logging($error, "ERROR", true);
        }

        // Get the graph
        curl_setopt($ch, CURLOPT_URL, $z_url_fetch);
        $output = curl_exec($ch);

        curl_close($ch);
		
		unset($ch);

		if(file_exists($filename_cookie)){
			$this->logging('> Deleting cookie file '.$filename_cookie, "INFO");
			unlink($filename_cookie);
		}else{
			$this->logging('> Unable to delete cookie file '.$filename_cookie, "INFO");
		}

        // Write file
        $fp = fopen($image_name, 'w');
        fwrite($fp, $output);
        fclose($fp);

        // Return filename
        $this->logging('> Received '.strlen($output).' bytes', "INFO");
        $this->logging('> Saved to '.$this->zabbixMediaPathImage.$filename, "INFO");
		
		$this->images[] = $this->zabbixMediaPathImage.$filename;
		
        return($filename);
    }
	
	private function addGraphs($varName,$info,$period,$periodHeader){
        $files = array();

        foreach($info as $aKey=>$anItem)
        {
            $graphFile = GraphImageById($anItem['graph']['graphid'],
                                        $this->graphWidth,$this->graphHeight,
                                        $anItem['graph']['graphtype'],
                                        $this->showLegend,$period);

            $this->data['GRAPHS_'.$varName][$aKey]['URL'] = $this->zabbixUrlMediaImage . $graphFile;
            $this->data['GRAPHS_'.$varName][$aKey]['PATH'] = $this->zabbixMediaPathImage . $graphFile;
        }

        $this->data['GRAPHS_'.$varName.'_LINK'] = $this->zabbixUrlBase.'/screens.php?elementid='.$info[0]['screen']['screenid'];
        $this->data['GRAPHS_'.$varName.'_HEADER'] = $info[0]['name'];
        $this->data['GRAPHS_'.$varName.'_PERIODHEADER'] = $periodHeader;

    }
	
	private function embedGraphs($graphs,$varName,$type){
		

        foreach($graphs as $aKey=>$anItem)
        {
			
			$image_type = pathinfo($this->data['GRAPHS_'.$varName][$aKey]['PATH'], PATHINFO_EXTENSION);
			$image_data = file_get_contents($this->data['GRAPHS_'.$varName][$aKey]['PATH']);
			$base64 = 'data:image/' . $image_type . ';base64,' . base64_encode($image_data);
			
            $this->data['GRAPHS_'.$varName][$aKey]['CID'] = $base64;
			$this->logging('> Embedded graph image ('.$image_type.') '.$this->data['GRAPHS_'.$varName][$aKey]['PATH'], "INFO");
        }
    }
	
	private function logging($msg, $log, $die=false){
		
		$full_msg = get_class($this)." -- ".$log." -- ".$msg;
		if ($log == "ERROR" && ($this->loggingLevel == 1 || $this->loggingLevel == 2 || $this->loggingLevel == 3 || $this->loggingLevel == 4)){
			syslog(LOG_INFO, $full_msg);
		}
		if ($log == "WARNING" && ($this->loggingLevel == 2 || $this->loggingLevel == 3 || $this->loggingLevel == 4)){
			syslog(LOG_INFO, $full_msg);
		}
		if ($log == "INFO" && ($this->loggingLevel == 3 || $this->loggingLevel == 4)){
			syslog(LOG_INFO, $full_msg);
		}
		if ($this->loggingLevel == 4){
			if ($this->source == 'commandline'){
				echo $full_msg."\n";
			}
		}
		if($die === true){
			echo json_encode(array('errors' => array($msg)));
			exit();
		}
	}
	
	private function mask($input=null){
		return "********************";
	}
	
	private function setVariable($name, $value, $mask=false){
		
		$this->logging("$name = ".(isset($mask) && $mask == true ? $this->mask($value) : $value), "INFO");
		$this->{$name} = $value;
	}
}

// CHECK REQUIRED LIBRARIES (Composer)
// (configure at same location as the script is running or load in your own central library)
// -- twig/twig                     https://twig.symfony.com/doc/3.x/templates.html

if (!class_exists(Environment::class)){
	echo json_encode(array('errors' => array(_("Cannot find Twig Environment Class.  Run 'composer require twig/twig' "))));
	exit();
}

if (!class_exists(ZabbixApi::class)){
	echo json_encode(array('errors' => array(_("Cannot find Zabbix Api Class.  Make sure class exists in /lib "))));
	exit();
}

if (!class_exists(HaloApi::class)){
	echo json_encode(array('errors' => array(_("Cannot find Halo Api Class.  Make sure class exists in /lib "))));
	exit();
}

// CHECK DIRECTORIES
if (!file_exists(__DIR__.'/images')) {
    mkdir(__DIR__.'/images', 0755, true);
}

if (!file_exists(__DIR__.'/tmp')) {
    mkdir(__DIR__.'/tmp', 0755, true);
}


// LOAD CONFIG and OVERWRITE VALUES WITH COMMANDLINE OR POST VALUES
if(file_exists(__DIR__.'/config/config.php')){
	require_once __DIR__.'/config/config.php';
	$params = $config;
}

// PROCESS REQUEST
if(getenv('REQUEST_METHOD') == 'POST'){
	$input = file_get_contents('php://input');
	$input = json_decode($input, true);
	$input['source'] = 'webhook';
} elseif ('cli' === PHP_SAPI) {
	$long_options = ["eventId:", "itemId:", "duration:", "haloClientSecret::","haloGrantType::","haloScope::","haloHost::","haloCustomFieldId","zabbixUser::","zabbixPassword::","zabbixApiUser::","zabbixApiPassword::","zabbixUrlBase::","verifyPeer::","loggingLevel::","criticalPriority::","warningPriority::","summary::","graphHeight::","graphWidth::","period::","showLegend::"];
	$opts = getopt('', $long_options);
	$input = $opts;
	$input['source'] = 'commandline';
} else {
	echo json_encode(array('errors' => array(_("Bad Request.  Must be POST or CLI"))));
	exit();
}

// ADD INPUT TO PARAMS
foreach ($input as $key => $value){
	if (isset($value) && !empty($value)) $params[$key] = $value;
}

// RUN ZABBIX HALO
$zabbixHalo = new ZabbixHalo($params);