<?php //
/* 
 * PHPWOL - Send wake on lan magic packet from php.
 * PHP Version 5.6.28
 * @package PHPWOL
 * @see https://github.com/andishfr/wake-on-lan.php/ GitHub project
 * @author Andreas Schaefer <asc@schaefer-it.net>
 * @copyright 2021 Andreas Schaefer
 * @license https://github.com/AndiSHFR/wake-on-lan.php/blob/master/LICENSE MIT License
 * @note This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 */


 /**
  * Wake On Lan function.
  *
	* @param string      $mac         The mac address of the host to wake
	* @param string      $ip          The hostname or ip address of the host to wake
	* @param string      $cidr        The cidr of the subnet to send to the broadcast address
	* @param string      $port        The udp port to send the packet to
  *
	* @return bool|string             false  = No error occured, string = Error message
	*/
  function wakeOnLan($mac, $ip, $cidr, $port, &$debugOut) {
    // Initialize the result. If FALSE then everything went ok.
    $wolResult = false;
    // Initialize the debug output return
    $debugOut = [];  
    // Initialize the magic packet
    $magicPacket = str_repeat(chr(0xFF), 6);
        
    $debugOut[] = __LINE__ . " : wakeupOnLan('$mac', '$ip', '$cidr', '$port' );"; 
    
    // Test if socket support is available
    if(!$wolResult && !extension_loaded('sockets')) {
      $wolResult = 'Error: Extension <strong>php_sockets</strong> is not loaded! You need to enable it in <strong>php.ini</strong>';
      $debugOut[] = __LINE__ . ' : ' . $wolResult;
    }
  
    // Test if UDP datagramm support is avalable	
    if(!array_search('udp', stream_get_transports())) {
      $wolResult = 'Error: Cannot send magic packet! Tranport UDP is not supported on this system.';
      $debugOut[] = __LINE__ . ' : ' . $wolResult;
    }
  
    // Validate the mac address
    if(!$wolResult) {
      $debug[] = __LINE__ . ' : Validating mac address: ' . $mac; 
      $mac = str_replace(':','-',strtoupper($mac));
      $debugOut[] = __LINE__ . ' : MAC = ' . $mac;
  
      if ((!preg_match("/([A-F0-9]{2}[-]){5}([0-9A-F]){2}/",$mac)) || (strlen($mac) != 17)) {
        $wolResult = 'Error: Invalid MAC-address: ' . $mac;
        $debugOut[] = __LINE__ . ' : ' . $wolResult;
      }
    }
  
    // Finish the magic packet
    if(!$wolResult) {
      $debugOut[] = __LINE__ . ' : Creating the magic paket'; 
      $hwAddress = '';
      foreach( explode('-', $mac) as $addressByte) {
        $hwAddress .= chr(hexdec($addressByte)); 
      }
      $magicPacket .= str_repeat($hwAddress, 16);
    }
      
    // Resolve the hostname if not an ip address
    if(!$wolResult && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ) {
      $debugOut[] = __LINE__ . ' : Resolving host :' . $ip;
      $tmpIp = gethostbyname($ip);
      if($ip==$tmpIp) {
        $wolResult = 'Error: Cannot resolve hostname "' . $ip . '".';
        $debugOut[] = __LINE__ . ' : ' . $wolResult;
      } else {
        $ip = $tmpIp; // Use the ip address
      }
    }
      
    // If $cidr is not empty we will use the broadcast address rather than the supplied ip address
    if(!$wolResult && '' != $cidr ) {
      $debugOut[] = __LINE__ . ' : CIDR is set to ' . $cidr . '. Will use broadcast address.';
      $cidr = intval($cidr);
      if($cidr < 0 || $cidr > 32) {
        $wolResult = 'Error: Invalid subnet size of ' . $cidr . '. CIDR must be between 0 and 32.';
        $debugOut[] = __LINE__ . ' : ' . $wolResult;			
      } else {
        // Create the bitmask long from the cidr value
        $netMask = -1 << (32 - (int)$cidr);
        // Create the network address from the long of the ip and the network bitmask
        $networkAddress = ip2long($ip) & $netMask; 
        // Calulate the size fo the network (number of ip addresses in the subnet)
        $networkSize = pow(2, (32 - $cidr));
        // Calculate the broadcast address of the network by adding the network size to the network address
        $broadcastAddress = $networkAddress + $networkSize - 1;
  
        $debugOut[] = __LINE__ . ' : $netMask = ' . long2ip($netMask);
        $debugOut[] = __LINE__ . ' : $networkAddress = ' . long2ip($networkAddress);
        $debugOut[] = __LINE__ . ' : $networkSize = ' . $networkSize;
        $debugOut[] = __LINE__ . ' : $broadcastAddress = ' . long2ip($broadcastAddress);
  
        // Create the braodcast address from the long value and use this ip
        $ip = long2ip($broadcastAddress);
      }
    }
  
    // Validate the udp port
    if(!$wolResult && '' != $port ) {
      $port = intval($port);
      if($port < 0 || $port > 65535 ) {
        $wolResult = 'Error: Invalid port value of ' . $port . '. Port must between 1 and 65535.';
        $debugOut[] = __LINE__ . ' : ' . $wolResult;			
      }
    }		
            
      // Can we work with socket_create/socket_sendto/socket_close?
      if(!$wolResult && function_exists('socket_create') ) {
      
        $debug[] = __LINE__ . ' : Calling socket_create(AF_INET, SOCK_DGRAM, SOL_UDP)';														
        // Create the socket
        $socket = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP); // IPv4 udp datagram socket
        if(!$socket) {				
          $errno = socket_last_error();
          $wolResult = 'Error: ' . $errno . ' - ' . socket_strerror($errno); 
          $debug[] = __LINE__ . ' : ' . $wolResult;																
        }
  
        if(!$wolResult) {
          $debug[] = __LINE__ . ' : Calling socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, true)';																	
          // Set socket options
          $socketResult = socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, true);
          if(0 >= $socketResult) {
            $wolResult = 'Error: ' . socket_strerror($socketResult); 
            $debug[] = __LINE__ . ' : ' . $wolResult;													
          }
        }
  
        if(!$wolResult) {
          $debug[] = __LINE__ . ' : Sending magic packet using socket-sendto()...';		
          $flags = 0;															
          $socket_data = socket_sendto($socket, $magicPacket, strlen($magicPacket), $flags, $ip, $port);
          if(!$socket_data) {
            $wolResult = 'Error: ' . socket_strerror($socketResult); 
            $debug[] = __LINE__ . ' : ' . $wolResult;													
            //DbOut("A magic packet of ".$socket_data." bytes has been sent via UDP to IP address: ".$addr.":".$port.", using the '".$function."()' function.");
           }
        }
        
        if($socket) {
          socket_close($socket);
          unset($socket);			 
        }
      
    } else 
      if(!$wolResult) {
        $wolResult = 'Error: Cannot send magic packet. Neither fsockopen() nor'
                   . ' socket_create() is available on this system.';
        $debugOut[] = __LINE__ . ' : ' . $wolResult;						
      }
    
    if(!$wolResult) $debugOut[] = __LINE__ . ' : Done.';
  
    return $wolResult;
  }
  

function safeGet($data, $key, $default) { 
  return isset($data) && isset($data[$key]) ? $data[$key] : $default; 
}

function endWithErrorMessage($message) {
  http_response_code(500);
	die('Internal Server Error! ' . $message);
}

function endWithJsonResponse($responseData, $filename = NULL) {

  if($responseData) {
    array_walk_recursive($responseData, function(&$value, &$key) {
      if(is_string($value)) $value = utf8_encode($value);
    });  
  }

	$jsonString = json_encode($responseData, JSON_PRETTY_PRINT);

	if(!$jsonString) endWithErrorMessage('Cannot convert response data to JSON.');

	header('Content-Length: ' . strlen($jsonString) );
	header('Content-Type: application/json');	
	header('Expires: Mon, 26 Jul 1997 05:00:00:00 GMT');
	header('Last-Modified: ' . gmdate('D, d M Y H:i:s'));
  header('Cache-Control: no-cache, must-revalidate');
	header('Pragma: no-cache');
  if($filename) {
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Transfer-Encoding: binary');
  }
  die($jsonString);	
}


/**
 * Initialize required variables 
 */
$configFilename = __DIR__ . DIRECTORY_SEPARATOR . 'config.json';
$requestMethod = $_SERVER['REQUEST_METHOD'];

$isSocketExtensionLoaded = intval(extension_loaded('sockets'));
$isDebugEnabled = intval(safeGet($_GET, 'debug', false));
$ajaxOperation = safeGet($_POST, 'aop', safeGet($_GET, 'aop', ''));


/**
 * See if we have any ajax request
 */
if('CONFIG.GET'===$ajaxOperation) {
  $jsonData = [];
  if(file_exists($configFilename)) {
    $jsonString = file_get_contents($configFilename);
    $jsonData = json_decode($jsonString, true);
  }
  endWithJsonResponse($jsonData);
} else

if('CONFIG.SET'===$ajaxOperation && 'POST'==$requestMethod) {
    $phpInput = file_get_contents('php://input');
    $jsonData = json_decode($phpInput);
    $jsonString = json_encode($jsonData, JSON_PRETTY_PRINT);
    if(!file_put_contents($configFilename, $jsonString)) {
      endWithErrorMessage('Cannot write configuration file.<br/>Please make sure the web server can write to the folder.');
    }
    endWithJsonresponse([ 'status' => 'OK']);  
} else

if('CONFIG.DOWNLOAD'===$ajaxOperation) {
  $jsonData = [];
  if(file_exists($configFilename)) {
    $jsonString = file_get_contents($configFilename);
    $jsonData = json_decode($jsonString, true);
  }
  endWithJsonResponse($jsonData, 'wake-on-lan-' . date('Ymd-His') . '.json' );
} else

if('HOST.CHECK'===$ajaxOperation) {
  $HOST_CHECK_PORTS = [ '3389' => '3389 (RDP)', '22' => '22 (SSH)', '80' => '80 (HTTP)', '443' => '443 (HTTPS)' ]; 
  $host = safeGet($_GET, 'host', null);
  if(!$host) endWithErrorMessage('Parameter host not set.');
  $responseData = [ 'error' => false, 'isUp' => false ];

  $errStr = false;
  $errCode = 0;
  $waitTimeoutInSeconds = 3; 

  foreach($HOST_CHECK_PORTS as $port=>$info) {
    if($responseData['isUp']) break;
    if($fp = @fsockopen($host,$port,$errCode,$errStr,$waitTimeoutInSeconds)){   
      fclose($fp);
      $responseData['isUp'] = true;
      $responseData['info'] = $info;
      $responseData['errCode'] = '';
      $responseData['errStr'] = '';
      $responseData['errorPort'] = '';
    } else {
    $responseData['isUp'] = false;
    $responseData['errCode'] = $errCode;
    $responseData['errStr'] = $errStr;
    $responseData['errorPort'] = $port;
   }    
  }

  return endWithJsonResponse($responseData);
} else

if('HOST.WAKEUP'===$ajaxOperation) {

	$responseData = [ 'error' => false, 'data' => '' ];
  $DEBUGINFO = [];

  $mac = safeGet($_GET, 'mac', '');

	// Call to wake up the host
	$MESSAGE = wakeOnLan(
    $mac
  , safeGet($_GET, 'host', '')
  , safeGet($_GET, 'cidr', '')
  , safeGet($_GET, 'port', '')
  , $debugOut
  );

	// If the request was with enabled debug mode then append the debug info to the response 
	// To enable debug mode add "&debug=1" to the url
	if($isDebugEnabled) $responseData['DEBUG'] = $DEBUGINFO;

  if($MESSAGE) {
    endWithErrorMessage($MESSAGE);
  } else {
    endWithJsonResponse([
      'info' => 'Magic packet has been sent for <strong>' . $mac. '</strong>. Please wait for the host to come up...'
    ]);
  }
} else {
  if(isset($_GET['aop'])) endWithErrorMessage('Invalid value for aop!');
}


?>
<!DOCTYPE html>
<html lang="de">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Weboberfläche zum Wecken von Computern per Wake-on-LAN.">
    <title>Wake On Lan</title>
    <style>
      :root {
        color-scheme: light;
        font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;
        --page-bg: #f5f7fb;
        --card-bg: #ffffff;
        --card-border: #e5e7eb;
        --text-primary: #1f2937;
        --text-secondary: #6b7280;
        --shadow-soft: 0 18px 45px rgba(15, 23, 42, 0.08);
        --status-offline: #9ca3af;
        --status-online: #16a34a;
        --status-waking: #f97316;
        --status-unknown: #94a3b8;
      }

      * { box-sizing: border-box; }

      body {
        margin: 0;
        background: var(--page-bg);
        color: var(--text-primary);
      }

      .page {
        max-width: 880px;
        margin: 0 auto;
        padding: 48px 24px 64px;
        display: flex;
        flex-direction: column;
        gap: 32px;
      }

      .page-header {
        display: flex;
        flex-direction: column;
        gap: 8px;
      }

      .page-header h1 {
        margin: 0;
        font-size: clamp(2.2rem, 4vw, 2.8rem);
        font-weight: 600;
        letter-spacing: -0.02em;
      }

      .page-header p {
        margin: 0;
        color: var(--text-secondary);
        font-size: 1rem;
        line-height: 1.6;
      }

      .device-grid {
        display: flex;
        flex-direction: column;
        gap: 20px;
      }

      .device-card {
        --status-color: var(--status-offline);
        background: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 18px;
        padding: 18px 22px;
        display: flex;
        align-items: center;
        gap: 18px;
        box-shadow: var(--shadow-soft);
        transition: border-color 0.25s ease, transform 0.25s ease, box-shadow 0.25s ease;
      }

      .device-card[data-status="online"] { --status-color: var(--status-online); }
      .device-card[data-status="waking"] { --status-color: var(--status-waking); }
      .device-card[data-status="offline"] { --status-color: var(--status-offline); }
      .device-card[data-status="unknown"] { --status-color: var(--status-unknown); }

      .device-card:hover {
        transform: translateY(-2px);
        border-color: rgba(59, 130, 246, 0.35);
        box-shadow: 0 22px 55px rgba(15, 23, 42, 0.12);
      }

      .device-button {
        width: 68px;
        height: 68px;
        border-radius: 20px;
        border: 0;
        background: rgba(148, 163, 184, 0.18);
        display: inline-flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: background 0.2s ease, transform 0.2s ease;
        color: var(--status-color);
      }

      .device-card[data-status="online"] .device-button { background: rgba(22, 163, 74, 0.12); }
      .device-card[data-status="waking"] .device-button { background: rgba(249, 115, 22, 0.18); }
      .device-card[data-status="offline"] .device-button { background: rgba(156, 163, 175, 0.18); }
      .device-card[data-status="unknown"] .device-button { background: rgba(148, 163, 184, 0.18); }

      .device-button:focus-visible {
        outline: 3px solid rgba(59, 130, 246, 0.45);
        outline-offset: 4px;
      }

      .device-button:hover { transform: scale(1.03); }
      .device-button:disabled { cursor: wait; opacity: 0.7; }

      .device-icon {
        width: 36px;
        height: 36px;
      }

      .device-icon svg {
        width: 36px;
        height: 36px;
        fill: currentColor;
      }

      .device-info {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }

      .device-label {
        font-size: 1.1rem;
        font-weight: 500;
        letter-spacing: -0.01em;
      }

      .device-status-text {
        font-size: 0.95rem;
        color: var(--text-secondary);
      }

      .empty-state {
        border: 1px dashed var(--card-border);
        border-radius: 16px;
        padding: 32px;
        text-align: center;
        color: var(--text-secondary);
        background: rgba(255, 255, 255, 0.65);
      }

      .api-hint {
        font-size: 0.95rem;
        color: var(--text-secondary);
        padding: 18px 22px;
        border-radius: 16px;
        border: 1px solid var(--card-border);
        background: rgba(255, 255, 255, 0.85);
      }

      .toast {
        position: fixed;
        right: 28px;
        bottom: 28px;
        padding: 14px 22px;
        border-radius: 14px;
        background: #1f2937;
        color: #ffffff;
        font-size: 0.95rem;
        box-shadow: 0 15px 35px rgba(15, 23, 42, 0.22);
        opacity: 0;
        transform: translateY(20px);
        pointer-events: none;
        transition: opacity 0.25s ease, transform 0.25s ease;
        min-width: 220px;
      }

      .toast[data-variant="success"] { background: #166534; }
      .toast[data-variant="error"] { background: #b91c1c; }

      .toast.is-visible {
        opacity: 1;
        transform: translateY(0);
      }

      @media (max-width: 640px) {
        .page { padding: 32px 16px 48px; }
        .device-card {
          padding: 16px 18px;
          border-radius: 14px;
        }
        .device-button {
          width: 60px;
          height: 60px;
          border-radius: 16px;
        }
      }
    </style>
  </head>
  <body>
    <main class="page">
      <header class="page-header">
        <h1>Wake On Lan</h1>
        <p>Tippe auf das Computer-Symbol, um den jeweiligen Rechner aufzuwecken. Die Liste zeigt nur die Kommentare aus deiner <code>config.json</code>.</p>
      </header>
      <section id="deviceList" class="device-grid" aria-live="polite"></section>
      <p class="api-hint">API: <code>?aop=HOST.WAKEUP&amp;mac=MAC-ADRESSE</code></p>
    </main>

    <div id="toast" class="toast" role="status" aria-live="polite"></div>

    <template id="device-template">
      <article class="device-card" data-status="offline">
        <button type="button" class="device-button" aria-label="Computer wecken">
          <span class="device-icon" aria-hidden="true">
            <svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
              <rect x="8" y="12" width="48" height="34" rx="6" ry="6"></rect>
              <rect x="22" y="46" width="20" height="4" rx="2"></rect>
              <rect x="16" y="52" width="32" height="4" rx="2"></rect>
            </svg>
          </span>
        </button>
        <div class="device-info">
          <div class="device-label"></div>
          <div class="device-status-text">Offline</div>
        </div>
      </article>
    </template>

    <script>
      (function() {
        const list = document.getElementById('deviceList');
        const template = document.getElementById('device-template');
        const toast = document.getElementById('toast');
        const devices = new Set();
        const statusLabels = {
          offline: 'Offline',
          online: 'Online',
          waking: 'Wecken',
          unknown: 'Keine Statusdaten'
        };

        const showToast = (message, variant = 'success') => {
          toast.textContent = message;
          toast.setAttribute('data-variant', variant);
          toast.classList.add('is-visible');
          clearTimeout(showToast.timer);
          showToast.timer = setTimeout(() => toast.classList.remove('is-visible'), 3200);
        };

        const setStatus = (card, status) => {
          const statusNode = card.querySelector('.device-status-text');
          card.dataset.status = status;
          statusNode.textContent = statusLabels[status] || status;
        };

        const updateStatus = (card) => {
          const host = card.dataset.host;
          if (!host) {
            setStatus(card, 'unknown');
            return;
          }
          if (card.dataset.statusRequest === 'running') {
            return;
          }
          card.dataset.statusRequest = 'running';
          fetch(`?aop=HOST.CHECK&host=${encodeURIComponent(host)}`)
            .then((response) => {
              if (!response.ok) {
                throw new Error('Status konnte nicht geladen werden.');
              }
              return response.json();
            })
            .then((data) => {
              if (data && data.isUp) {
                setStatus(card, 'online');
              } else {
                setStatus(card, 'offline');
              }
            })
            .catch(() => {
              setStatus(card, 'offline');
            })
            .finally(() => {
              delete card.dataset.statusRequest;
            });
        };

        const wakeDevice = (card) => {
          const mac = card.dataset.mac;
          if (!mac) {
            showToast('Keine MAC-Adresse gefunden.', 'error');
            return;
          }
          const button = card.querySelector('.device-button');
          const params = new URLSearchParams({ aop: 'HOST.WAKEUP', mac });
          if (card.dataset.host) params.append('host', card.dataset.host);
          if (card.dataset.cidr) params.append('cidr', card.dataset.cidr);
          if (card.dataset.port) params.append('port', card.dataset.port);

          button.disabled = true;
          setStatus(card, 'waking');
          fetch(`?${params.toString()}`)
            .then((response) => {
              if (!response.ok) {
                return response.text().then((text) => { throw new Error(text || 'Wake-on-LAN fehlgeschlagen.'); });
              }
              return response.json();
            })
            .then((data) => {
              const message = (data && data.info) ? data.info.replace(/<[^>]+>/g, '') : 'Magic Packet gesendet.';
              showToast(message, 'success');
            })
            .catch((error) => {
              const cleanMessage = (error.message || 'Wake-on-LAN fehlgeschlagen.').replace(/<[^>]+>/g, '');
              showToast(cleanMessage, 'error');
            })
            .finally(() => {
              button.disabled = false;
              setTimeout(() => updateStatus(card), 4000);
            });
        };

        const createCard = (entry) => {
          const fragment = template.content.cloneNode(true);
          const card = fragment.querySelector('.device-card');
          const label = card.querySelector('.device-label');
          const button = card.querySelector('.device-button');

          const comment = entry.comment && entry.comment.trim();
          label.textContent = comment || entry.mac || 'Unbenannter Eintrag';
          button.setAttribute('aria-label', `${label.textContent} wecken`);

          card.dataset.mac = entry.mac || '';
          card.dataset.host = entry.host || '';
          card.dataset.cidr = entry.cidr || '';
          card.dataset.port = entry.port || '';

          button.addEventListener('click', (event) => {
            event.stopPropagation();
            wakeDevice(card);
          });

          card.addEventListener('keyup', (event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              wakeDevice(card);
            }
          });

          card.tabIndex = 0;
          card.setAttribute('role', 'group');
          card.setAttribute('aria-label', label.textContent);

          setStatus(card, 'offline');
          devices.add(card);
          setTimeout(() => updateStatus(card), 200);
          return card;
        };

        const renderDevices = (config) => {
          list.innerHTML = '';
          devices.clear();
          if (!Array.isArray(config) || config.length === 0) {
            const empty = document.createElement('div');
            empty.className = 'empty-state';
            empty.textContent = 'Keine Einträge vorhanden. Ergänze deine config.json, um hier Computer zu sehen.';
            list.appendChild(empty);
            return;
          }
          config.forEach((entry) => {
            list.appendChild(createCard(entry));
          });
        };

        const loadConfig = () => {
          fetch('?aop=CONFIG.GET')
            .then((response) => {
              if (!response.ok) {
                throw new Error('Konfiguration konnte nicht geladen werden.');
              }
              return response.json();
            })
            .then((config) => {
              renderDevices(config);
            })
            .catch((error) => {
              list.innerHTML = '';
              const empty = document.createElement('div');
              empty.className = 'empty-state';
              empty.textContent = (error.message || 'Konfiguration konnte nicht geladen werden.');
              list.appendChild(empty);
            });
        };

        loadConfig();
        setInterval(() => { devices.forEach((card) => updateStatus(card)); }, 15000);
      })();
    </script>
  </body>
</html>
