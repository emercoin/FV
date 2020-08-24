#!/usr/bin/php
<?php
// Emercoin File Validator (FV)
// License: BSD 
// Author: Oleg Khovayko (olegarch)
// Created: Aug, 23, 2020

// URL for connect to Emercoin wallet 
$emcCONNECT = "http://user:secret_pass@localhost:6662";

// Hash algorithm for using
$algo = "sha256";

//------------------------------------------------------------------------------
// Performs NVS-request to EMC wallet
// Returns JSON of response result. Exit with err print, if error
// Example:
// $ret = EMC_req('name_show', array('val:emercoin'));
function EMC_req($cmd, $params) {
  global $emcCONNECT;
  // Prepares the request
  $request = json_encode(array(
    'method' => $cmd,
    'params' => $params,
    'id' => '1'
  ));
  // Prepare and performs the HTTP POST
  $opts = array ('http' => array (
    'method'  => 'POST',
    'header'  => 'Content-type: application/json',
    'content' => $request
  ));
  do {
    $fp = @fopen($emcCONNECT, 'rb', false, stream_context_create($opts));
    if(!$fp)
      break;
    $rc = json_decode(stream_get_contents($fp), true);
    $er = $rc['error'];
    if(!is_null($er)) {
      printf("ERROR: %s\n", $er);
      break;
    }
    return $rc['result'];
  } while(false);
  // Eror handler
  printf("Unable fetch data from EMC-node with request: [%s] and params:\n", $cmd);
  print_r($params);
  exit(1);
} // EMC_req

//------------------------------------------------------------------------------
// Sanity check for assurance - all charas from $str within charest $set
// Exit, if error
function Sanity($str, $set): void {
    $len = strlen($str);
    $bad = strspn($str, $set);
    if($len != $bad) {
        printf("String [%s] contains unallowed symbol=%c, not specified within [%s], in the position %d\n", 
                $str, ord($str[$bad]), $set, $bad);
        exit(1);
    }
} // Sanity

//------------------------------------------------------------------------------
// Validate single signature line
// Params:
//   $line       : signature line
//   $search_key : NVS search key
//  Return 0 if OK, or 1 if error
// Example:
// $rc = validate_signature(
//         'fv:sha256=169dc5dd293cd82f84737055403ae87a62008072d785376f56f6d309288a092a', 
//         'SIG=emercoin|100|IH0yysgQpP1xIjRcJPrWaDVrl9B35BfrNcgOdwNm1gjFeE2zpKZZooSd55LydWlPnnlfnLiI+2Q1VUzzsD/8irE=');
function validate_signature($line, $search_key) {
  // echo("\t$line\n");
  list($validator, $score, $sig) = explode('|', $line);
  if(!isset($sig)) {
      echo("Invalid signature line[". $line ."], validation *FAIL*\n");
      return 1;
  }
  $validator = preg_replace('/SIG=/', '', $validator);
  $valnvs = EMC_req('name_show', array("val:" . $validator));
  // print_r($valnvs);
  $sigaddr = $valnvs['address'];
  $verstr = join('|', array($validator, $score, $search_key));
  // echo("verstr=$verstr;\n");
  $valresult = EMC_req('verifymessage', array($sigaddr, $sig, $verstr));
  $freetext = preg_replace('/[^[:print:]]/', '', $valnvs['value']);
  printf("\t%s [%s] created %s; Signature %s\n", $validator, $freetext, date('Y-m-d h:m', $valnvs['time']), $valresult? "PASSED" : "*FAIL*");
  return 1 ^ $valresult;
} // validate_signature

//------------------------------------------------------------------------------
// MAIN
// Help print, if no params
if($argc == 1) {
  printf("Emercoin File Validator\n");
  printf("Usage:\n\t%s fname [validatorID|score]\n", $argv[0]);
  printf("\tIf specified fname only, validate fname with Emercoin FV service.\n");
  printf("\tIf specified fname and validatorID, generates validation signature.\n");
  printf("Example:\n\t%s emercoin-0.7.10-win64-setup.exe 'emercoin|100'\n\n", $argv[0]);
  exit(0);
}

// Just test wallet connection with getinfo
if($argv[1] === '-getinfo') {
  echo("getinfo test started\n");
  $getinfo = EMC_req('getinfo', array());
  print_r($getinfo);
  exit(0);
}

// Build search key from filename argv[1]
$fname = $argv[1];
if(!file_exists($fname)) {
  printf("%s: Missing input file: %s\n", $argv[0], $argv[1]);
  exit(1);
}

$search_key = "fv:" . $algo . "=" . hash_file($algo, $fname);
// $search_key = "fv:sha256=169dc5dd293cd82f84737055403ae87a62008072d785376f56f6d309288a092a";
// printf("Skey=%s\n", $search_key);

// Presents 2nd param 'score|validator' - program runs in signature generation mode
if($argc > 2) {
    // Generate signature with specific validator name and score
    list($validator, $score) = explode('|', $argv[2]);
    Sanity($validator, "abcdefghijklmnopqrstuvwxyz-.");
    Sanity($score, "0123456789");
    $valnvs = EMC_req('name_show', array("val:" . $validator));
    $sigaddr = $valnvs['address'];
    $sigmsg = join('|', array($validator, $score, $search_key));
    // printf("sigmsg=[%s]\n", $sigmsg);
    $signature = EMC_req('signmessage', array($sigaddr, $sigmsg));
    echo("FV signature for upload to NVS FV-record:\n");
    echo("NVS Key:\n\t$search_key\n");
    echo("Signature line:\n\tSIG=" . join('|', array($validator, $score, $signature)) . "\n\n");
    exit(0);
} // Generate signature

// No 2nd param - program valudetes signature(s) for specified file
$valnvs = EMC_req('name_show', array($search_key));
// print_r($valnvs);

printf("File %s; FV-record created: %s\n\nFile info from NVS:\n", $fname, date('Y-m-d h:m', $valnvs['time']));
$lines = explode(PHP_EOL, $valnvs['value']);

$rc = 2; // Error, if no any signature!

// Print free form file info, ignore '^SIG=\w*' signature lines
foreach($lines as $line)
  if(strpos($line, "SIG=") !== 0)
    echo("\t" . preg_replace('/[^[:print:]]/', '', $line) . "\n");
  else
    $rc = 0;

// Validate signatures and print out
echo("\nValidation results:\n");
foreach($lines as $line) 
  if(strpos($line, "SIG=") === 0)
    $rc |= validate_signature($line, $search_key);

exit($rc);
?>
