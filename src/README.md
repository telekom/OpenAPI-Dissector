# `openapi.lua`

This script contains code that handles the Wireshark dissector API.

It registers itself as a postdissector and looks for HTTP2 packets. It contains
some logic to distinguish http2 streams, read information about those packets
and find correlations between requests and responses.

After finding requests/responses it tries to look up the path specifications
from the previously generated openapi specification and runs the json validator
with the given spec and some additional information about the packet.

For callbacks it keeps track of registered URLs and on match it loads the
corresponding spec instead of a path spec.

After the validation is done it adds some information to the packets, like the
specification document, name of operation, related packets, etc. On errors it
tries to highlight the packets in the packet list (this sometimes conflicts
with user defined coloring rules).

Additionally it marks unidentified JSON data for Wireshark, so the JSON
dissector is loaded and contained data gets listed in the packet details.

The script also automatically adds Wiresharks http2 dissector to data on TCP
ports 7777 and 8080 (which are commonly used by 5G core implementations).

# `json_validator.lua`

This script contains all of the code for the actual validation and some helper
funtions for resolving references inside of the previously generated openapi
specification data.

Its main entrypoint is the `validate_raw_json` method, which as arguments takes
a string of JSON data, a schema, a base path (mostly for logging purposes), a
reference to a list for errors and a dictionary of some extra information (e.g.
type of packet: request/response and information about parameters used for
callbacks).

Using json.lua the raw json gets parsed and `validate_json` is being called,
with mainly the same parameters just with the parsed json instead.

The `validate_json` method is mainly used to delegate validation to various
sub-validators (for e.g. strings or integers), but some simple cases like `null`
data and enums are validated directly inside of that function.

When oneOf/anyOf/allOf properties are defined data is getting passed to the
`validate_multiple` function, which returns a tuple containing the number of
valid and invalid data types from the list of defined schemas. It also has
basic support for discriminators used in combination with oneOf.

For other data types like `object`, `array`, `string`, `number`, etc a
corresponding subvalidator is being loaded. References to those subvalidators
are defined in the `json_validators` dictionary, but naming of the functions
mainly follows the type names in form of `validate_json_$type` anyway, so
they are easy to spot.

Most subvalidators are relatively simple, e.g. for strings there is some pattern
matching and for numbers there are some range checks, but `array` and `object`
validators are a bit more complicated as they need to check for subelements as
well.

Functionality inside of the subvalidators is mostly split into blocks so it
should be relatively easy to get an overview of how they are working.
