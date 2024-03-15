Mostly undocumented test code.

## `test.lua`

Runs a validation outside of Wireshark for quickly repeatable testing.

Takes a few arguments:

- http method
- path
- http status code of response
- request or response data
- "request" or "response" (to identify what is being looked for)
- optional: path to specific schema, separated by semicolon, e.g. `TS29510_Nnrf_NFManagement.yaml;CreateSubscription;callbacks;onNFStatusEvent;{$request.body#/nfStatusNotificationUri};post`, useful for manually specifying callback spec

## `apply-testcases.py`

Takes a few arguments:

- path to a txt file
- index of line in txt file
- optional: path to specific schema as described above

The txt file contains per line separated by space:

- http method
- path
- hex encoded request data
- http status code of response
- response data
- source filename of test data
- optional: path to specific schema as described above

## `extract-testcases.py`

Takes a path to a pcap as argument and returns a testcases txt as described
above.

Needs modification to pyshark, adding a `-2` argument to the tshark call.

## `*.txt`

Previously extracted test cases as described above, partially modified by hand
to e.g. add schemas for callbacks.
