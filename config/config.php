<?php
$config = array(
	//'haloClientId' => '',
	//'haloClientSecret' => '',
	//'haloGrantType' => 'client_credentials',
	//'haloScope' => 'all',
	//'haloHost' => '',
	//'haloCustomFieldId' => '',
	//'haloCustomFieldName' => '',
	//'haloTicketTypeId' => '',
	//'haloTicketPriorityId' => '',
	//'haloTicketClientId' => '',
	//'haloTicketTeam' => '',
	//'haloTicketCategory1' => '',
	//'haloTicketUsername' => '',
	//'zabbixUser' => '',
	//'zabbixPassword' => '',
	//'zabbixApiUser' => '',
	//'zabbixApiPassword' => '',
	//'zabbixUrlBase' => '',
	//'zabbixUrlMedia' => '',
	'verifyPeer' => true, // SETS curl_setopt ($curl, CURLOPT_SSL_VERIFYPEER, TRUE)
	'httpProxy' => '',
	'loggingLevel' => 1,  //0=none,1=errors only,2=errors and warnings,3=info,4=info + screen output
	'summary' => "{{ HOST_NAME|raw }}:  ({{ EVENT_SEVERITY }}) {{ EVENT_NAME|raw }}",
	//'duration' => 10,
	//'eventId' => 29115658,
	//'itemId' => 36915,
	//'eventValue' => 1, //Use for commandline testing SET 0 = recovery 1 = Triggered/Active
	'graphMatch' => 'any',
	'graphHeight' => 120,
	'graphWidth' => 300,
	'period' => '20m',
	'periodHeader' => 'Last 20 minutes',
	'showLegend' => '',
	'test' => 0,
);

?>

