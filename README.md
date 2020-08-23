# FV - File Validator

Blockchain-based file validation service

Program fv.php connects to the local Emercoin wallet node. Please, edit
following line for setup the actual EMC wallet credentials:

$emcCONNECT = "http://user:secret_pass@localhost:6662";

Script usage:

1. Generate signatures:
-----------------------

./fv.php filename 'validator|score'

Example:
./fv.php emercoin-0.7.10-win64-setup.exe "olegarch|100"

Program returns NVS key and signature for uploat to Emercoin NVS:


FV signature for upload to NVS fv-record:
NVS Key:
	fv:sha256=169dc5dd293cd82f84737055403ae87a62008072d785376f56f6d309288a092a
Signature line:
	SIG=olegarch|100|H32Bp3cLoqBFvlyUIIXLrKX3TD+IG2aX2dmegy4oIxGEWeKBw9YTITKWaFWM4UdejEgpH5em4Gi/ZfoZFU69Owk=


2. Validate file:
-----------------


./fv.php filename

Example:
./fv.php emercoin-0.7.10-win64-setup.exe

Program check al signatures, specific for this file, ns will print out:


File emercoin-0.7.10-win64-setup.exe; FV-record created: 2020-08-22 11:08

File info from NVS:
	Emercoin core wallet, full node
	File: emercoin-0.7.10-win64-setup.exe
	Download: https://emercoin.com/en/for-coinholders#download

Validation results:
	emercoin [Emercoin File Validator] created 2020-08-20 05:08; Signature PASSED
	olegarch [Oleg Khovayko FV] created 2020-08-20 02:08; Signature PASSED

