<?php
function wakeOnLan($mac, $ip, $cidr, $port) {
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



$mac = '88:d7:f6:50:eb:b4';
$ip = '2.11.142.245';
$cidr = '24';
$port = '7';

$result = wakeOnLan($mac, $ip, $cidr, $port);

?>
