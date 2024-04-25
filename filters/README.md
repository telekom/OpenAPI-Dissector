# Custom filters

You can add a file called `openapi_fields.lua` to your Wireshark plugin directory to extract data that
can be used for filtering requests and responses.

The basic structure of this file should look as follows:

```lua
local openapi_fields = {}
local openapi_field_types = {}

-- add your rules here


return {openapi_fields=openapi_fields, openapi_field_types=openapi_field_types}
```

A rule consists of a filter name that can later be used inside of Wireshark and
a list of paths within the JSON structures of requests and responses.

You can either use full paths, or just use the name of the lowest element:

```lua
openapi_fields["nfInstanceId"] = "root[nfProfile][nfInstanceId]"
-- or
openapi_fields["nfInstanceId"] = "all[nfInstanceId]"
```

It's also possible to apply a single filter name to multiple elements:

```lua
openapi_fields["smfId"] = {"all[nfInstanceId]", "all[smfId]"}
```

The values matched by these filters are normally interpreted as strings, which
works in most cases where you just want to find identical elements, but if you
have a use case for actually interpreting data in a different way (e.g., for
numeric comparison) you can use all data types Wireshark makes available for
its [Lua API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html#lua_class_ProtoField).

```lua
openapi_fields["port"] = "all[port]"
openapi_field_types["port"] = "uint16"
```

To make it easier to find the generated paths you can enable the data tree
inside of Wiresharks preferences for the OpenAPI dissector. It will then be
added to the packet dissection details.

## Background information

We wanted to create a way to filter on certain data inside of requests and responses
described by OpenAPI documents, but unfortunately we ran into a few issues:

For one Wireshark doesn't seem to support the dynamic creation of dissector tree
entries, we'd need to pre-generate a list of all possible values to be filled.

But even if that would have worked (which it probably would have), two related issues
still remain:

For invalid data and especially in cases of data structures described using
oneOf/anyOf/allOf schemas we don't really know which components are actually being
used.

The only option that will always be available is the raw JSON data structure, but
unfortunately objects might be nested or sometimes using different names (e.g.,
NfInstanceId, which often gets a more specific name like `amfId`).
Using the raw JSON key path would still make it hard to filter on all operations
that are related to some specific data.

To solve this issue we implemented a more manual approach to this issue, as
described above.
