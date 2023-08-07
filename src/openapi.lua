local openapi_proto = Proto("openapi", "OpenAPI")

local openapi_spec = require "openapi_spec"
local json = require "json"
local json_validator = require "json_validator"

local json_dissector = Dissector.get("json")

local stream_map = {}
local packet_map = {}
local resp_map = {}
local callback_map = {}

local f_http2_data_data = Field.new("http2.data.data")
local f_http2_length = Field.new("http2.length")
local f_http2_headers = Field.new("http2.headers")
local f_http2_headers_method = Field.new("http2.headers.method")
local f_http2_headers_host = Field.new("http2.headers.authority")
local f_http2_headers_path = Field.new("http2.headers.path")
local f_http2_headers_status = Field.new("http2.headers.status")
local f_http2_headers_content_type = Field.new("http2.headers.content_type")
local f_http2_headers_location = Field.new("http2.headers.location")
local f_http2_flags_end_stream = Field.new("http2.flags.end_stream")
local f_http2_type = Field.new("http2.type")
local f_http2_streamid = Field.new("http2.streamid")
local f_tcp_stream = Field.new("tcp.stream")

local DEBUG = false

function debug_print(...)
  if DEBUG then
    print(...)
  end
end

function has_value(table, value)
  for i, v in pairs(table) do
    if v == value then
      return true
    end
  end
  return false
end

openapi_proto.fields.substream_id = ProtoField.uint32("openapi.substream_id", "Sub-Stream ID (generated)")
openapi_proto.fields.response_found = ProtoField.bool("openapi.response.found", "Response Found")
openapi_proto.fields.summary = ProtoField.string("openapi.summary", "Request Summary")
openapi_proto.fields.spec = ProtoField.string("openapi.spec", "Specification File")
openapi_proto.fields.description = ProtoField.string("openapi.description", "Request Description")
openapi_proto.fields.operation = ProtoField.string("openapi.operation", "Operation")
openapi_proto.fields.error = ProtoField.string("openapi.error", "Error")
openapi_proto.fields.warning = ProtoField.string("openapi.warning", "Warning")

-- request headers
openapi_proto.fields.request_headers_frame = ProtoField.framenum("openapi.request.headers_frame", "Request Headers Frame")
openapi_proto.fields.request_method = ProtoField.string("openapi.request.method", "Request Method")
openapi_proto.fields.request_path = ProtoField.string("openapi.request.path", "Request Path")
openapi_proto.fields.request_path_valid = ProtoField.bool("openapi.request.path_valid", "Request Path Valid")
openapi_proto.fields.request_error = ProtoField.string("openapi.request.error", "Request Error")
openapi_proto.fields.request_warning = ProtoField.string("openapi.request.warning", "Request Warning")

openapi_proto.fields.callback = ProtoField.framenum("openapi.callback", "Callback")
openapi_proto.fields.callback_registration = ProtoField.framenum("openapi.callback_registration", "Callback Registration")

-- request data
openapi_proto.fields.request_data = ProtoField.string("openapi.request.data", "Request Data")
openapi_proto.fields.request_data_frame = ProtoField.framenum("openapi.request.data_frame", "Request Data Frame")

-- response headers
openapi_proto.fields.response_headers_frame = ProtoField.framenum("openapi.response.headers_frame", "Response Headers Frame")
openapi_proto.fields.response_status = ProtoField.uint32("openapi.response.status", "Response Status")
openapi_proto.fields.response_location = ProtoField.string("openapi.response.location", "Response Redirect Location")
openapi_proto.fields.response_error = ProtoField.string("openapi.response.error", "Response Error")
openapi_proto.fields.response_warning = ProtoField.string("openapi.response.warning", "Response Warning")

-- response data
openapi_proto.fields.response_data = ProtoField.string("openapi.response.data", "Response Data")
openapi_proto.fields.response_data_frame = ProtoField.framenum("openapi.response.data_frame", "Response Data Frame")

function openapi_proto.init()
  stream_map = {}
  resp_map = {}
  if gui_enabled() then
    set_color_filter_slot(1, "openapi.error || openapi.request.error || openapi.response.error")
  end

end

function hexdecode(hex)
  return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

local validators = {}
validators["application/json"] = json_validator.validate_raw_json

function validate_request(request_info, request_spec, callbacks)
  local callback_spec = {}
  if callbacks then
    for i, v in pairs(callbacks) do
      for j, w in pairs(v) do
        callback_spec[j] = {}
        callback_spec[j]["key"] = i
        callback_spec[j]["path_spec"] = openapi_get_value(w, string.lower(request_info["method"]))
        callback_spec[j]["source"] = request_info
      end
    end
  end

  local content_spec = openapi_get_value(request_spec, "content")
  if content_spec == nil then return end

  if validators[request_info["content_type"]] == nil then
    for k, v in pairs(validators) do
      if rex_pcre2.match(k, "^application/.*json") then
        if validators[k] == nil then
          validators[k] = validators["application/json"]
        end
        request_info["content_type"] = k
      end
    end
  end

  if validators[request_info["content_type"]] ~= nil and content_spec[request_info["content_type"]] ~= nil then
    local content_spec = openapi_get_value(content_spec, request_info["content_type"])
    local schema = openapi_get_value(content_spec, "schema")
    local errors = {}
    local extra_info = {}
    extra_info["type"] = "request"
    extra_info["callback_map"] = callback_map
    extra_info["callback_spec"] = callback_spec
    local valid = validators[request_info["content_type"]](request_info["data"], schema, "root", errors, extra_info)
    local out = ""
    if not valid then
      for _, err in pairs(errors) do
        table.insert(request_info["errors"], "Validation: " .. err)
      end
    end
    return valid
  end
end

function validate_response(request_info, response_info, response_spec)
  local content_spec = openapi_get_value(response_spec, "content")
  if content_spec == nil then return end

  if validators[response_info["content_type"]] == nil then
    for k, v in pairs(validators) do
      if rex_pcre2.match(k, "^application/.*json") then
        if validators[k] == nil then
          validators[k] = validators["application/json"]
        end
        response_info["content_type"] = k
      end
    end
  end

  if validators[response_info["content_type"]] ~= nil and content_spec[response_info["content_type"]] ~= nil then
    local content_spec = openapi_get_value(content_spec, response_info["content_type"])
    local schema = openapi_get_value(content_spec, "schema")
    local errors = {}
    local extra_info = {}
    extra_info["type"] = "response"
    extra_info["callback_map"] = callback_map
    extra_info["callback_spec"] = {}
    local valid = validators[response_info["content_type"]](response_info["data"], schema, "root", errors, extra_info)
    local out = ""
    for i, v in pairs(errors) do
      out = out .. v .. "\n"
    end
    if not valid then
      for _, err in pairs(errors) do
        table.insert(response_info["errors"], "Validation: " .. err)
      end
    end
    return valid
  end
end

function openapi_resolve_reference(ref)
    local refval = openapi_spec["components"][ref]
    if refval == nil then
         error('Referenced component ' .. ref .. ' not found')
    end
    if refval['$ref'] ~= nil then
        return openapi_resolve_reference(refval['$ref'])
    else
        return refval
    end
end

function openapi_get_value(dict, key)
    if dict['$ref'] ~= nil then
        return openapi_resolve_reference(dict['$ref'])[key]
    else
        return dict[key]
    end
end

function find_callback(_host, _path, _method)
  if _host and _path then
    if callback_map["http://" .. _host .. _path] ~= nil then
      return callback_map["http://" .. _host .. _path]
    elseif callback_map["https://" .. _host .. _path] ~= nil then
      return callback_map["https://" .. _host .. _path]
    end
  end
end

function find_path_specs(_method, _path, _search, _host)
    local search
    local method
    if _search == nil then
      search = openapi_spec["path_patterns"]
      method = string.lower(_method)
    else
      search = _search
      method = _method
    end

    local path = string.match(string.sub(_path, 2), "[^?]+") -- remove / from start

    if path == nil or string.len(path) == 0 then
      if search[method] ~= nil then
        debug_print("returning method " .. method .. " foo")
        return search[method]
      else
        debug_print("returning method foo")
        return {}
      end
    else
      local path_part = string.match(path, "[^/?]+")
      local results = {}

      debug_print("path part: ".. path_part)
      for pattern, subtable in pairs(search) do
        if rex_pcre2.match(path_part, pattern) then
          for _, entry in pairs(find_path_specs(method, string.sub(path, string.len(path_part)+1), subtable, nil)) do
            if type(entry) == "number" then
              table.insert(results, openapi_spec["path_specs"][entry])
            else
              table.insert(results, entry)
            end
          end
        end
      end

      return results
    end
end

local substreamnums = {}
function openapi_proto.dissector(buf, pinfo, tree)
  -- ignore non-tcp
  local tcp_stream = f_tcp_stream()
  if not tcp_stream then return end

  -- ignore non-http2
  local http2_streamid = f_http2_streamid()
  if not http2_streamid then return end

  -- ignore everything but headers and data
  local http2_type = f_http2_type().value
  if http2_type ~= 0 and http2_type ~= 1 then return end

  local streamid = string.format("%s/%s", tcp_stream, http2_streamid)
  if stream_map[streamid] == nil then
    stream_map[streamid] = {}
    stream_map[streamid]["request"] = {}
    stream_map[streamid]["response"] = {}
  end
  if substreamnums[streamid] == nil then
    substreamnums[streamid] = 0
  end

  if not pinfo.visited then
    local http2_flags_end_stream = f_http2_flags_end_stream().value
    packet_map[pinfo.number] = substreamnums[streamid]
    if http2_flags_end_stream then
      substreamnums[streamid] = substreamnums[streamid] + 1
    end
  end

  if stream_map[streamid][packet_map[pinfo.number]] == nil then
    stream_map[streamid][packet_map[pinfo.number]] = {}
  end

  local stream_info = stream_map[streamid][packet_map[pinfo.number]]
  local packet_type = nil
  local request_info = nil
  local response_info = nil
  if packet_map[pinfo.number] % 2 == 0 then
    packet_type = "request"
    request_info = stream_map[streamid][packet_map[pinfo.number]]
    response_info = stream_map[streamid][packet_map[pinfo.number]+1]
  else
    packet_type = "response"
    request_info = stream_map[streamid][packet_map[pinfo.number]-1]
    response_info = stream_map[streamid][packet_map[pinfo.number]]
    response_info["found"] = true
  end

  if request_info ~= nil then
    if request_info["errors"] == nil then request_info["errors"] = {} end
    if request_info["warnings"] == nil then request_info["warnings"] = {} end
  end
  if response_info ~= nil then
    if response_info["errors"] == nil then response_info["errors"] = {} end
    if response_info["warnings"] == nil then response_info["warnings"] = {} end
  end

  -- ignore visited
  if pinfo.visited then
    pinfo.cols.protocol = tostring(pinfo.cols.protocol) .. "/OpenAPI"
    if pinfo.number == request_info["headers_frame"] then
      pinfo.cols.info = string.format("OpenAPI Request-Header %s %s", request_info["method"], request_info["path"])
    end
    if pinfo.number == request_info["data_frame"] then
      pinfo.cols.info = string.format("OpenAPI Request-Data (%s bytes)", request_info["data_length"])
    end
    if pinfo.number == response_info["headers_frame"] then
      pinfo.cols.info = string.format("OpenAPI Response-Headers (%s)", response_info["status"])
    end
    if pinfo.number == response_info["data_frame"] then
      pinfo.cols.info = string.format("OpenAPI Response-Data (%s bytes)", response_info["data_length"])
    end

    local toptree = tree:add(openapi_proto, "OpenAPI")
    local subtree = toptree:add(openapi_proto, "Operation")
    local request_subtree = toptree:add(openapi_proto, "Request")
    local response_subtree = toptree:add(openapi_proto, "Response")

    if #request_info["warnings"] > 0 then
      for _, warn in pairs(request_info["warnings"]) do
        request_subtree:add(openapi_proto.fields.request_warning, warn):set_generated()
      end
    end
    if #request_info["errors"] > 0 then
      request_subtree:add_expert_info(PI_RESPONSE_CODE, PI_ERROR, "Error")
      for _, err in pairs(request_info["errors"]) do
        request_subtree:add(openapi_proto.fields.request_error, err):set_generated()
      end
    end

    if #response_info["warnings"] > 0 then
      for _, warn in pairs(response_info["warnings"]) do
        response_subtree:add(openapi_proto.fields.response_warning, warn):set_generated()
      end
    end
    if #response_info["errors"] > 0 then
      response_subtree:add_expert_info(PI_RESPONSE_CODE, PI_ERROR, "Error")
      for _, err in pairs(response_info["errors"]) do
        response_subtree:add(openapi_proto.fields.response_error, err):set_generated()
      end
    end

    subtree:add(openapi_proto.fields.substream_id, packet_map[pinfo.number]):set_generated()
    subtree:add(openapi_proto.fields.response_found, response_info["found"]):set_generated()
    if request_info["spec"] ~= nil then
      subtree:add(openapi_proto.fields.spec, request_info["spec"]):set_generated()
    end
    if request_info["summary"] ~= nil then
      subtree:add(openapi_proto.fields.summary, request_info["summary"]):set_generated()
    end
    if request_info["operation"] ~= nil then
      subtree:add(openapi_proto.fields.operation, request_info["operation"]):set_generated()
    end
    if request_info["description"] ~= nil then
      subtree:add(openapi_proto.fields.description, request_info["description"]):set_generated()
    end

    if not request_info["parsed"] then
      local callback = find_callback(request_info["host"], request_info["path"], request_info["method"])
      local path_specs = {}

      if callback then
        request_info["callback_registration"] = callback["source"]["headers_frame"]

        if callback["source"]["callbacks"] == nil then
          callback["source"]["callbacks"] = {}
        end
        if has_value(callback["source"]["callbacks"], request_info["headers_frame"]) == false then
          table.insert(callback["source"]["callbacks"], request_info["headers_frame"])
        end

        table.insert(path_specs, callback["path_spec"])
      else
        path_specs = find_path_specs(request_info["method"], request_info["path"], nil, request_info["host"])
      end

      request_info["path_valid"] = false
      if #path_specs > 0 then
        path_spec = path_specs[1] -- TODO: allow multiple matching specs or sort to correct NF?

        request_info["path_valid"] = true
        if path_spec["requestBody"] ~= nil then
          validate_request(request_info, path_spec["requestBody"], path_spec["callbacks"])
        end

        if path_spec["responses"] ~= nil then
          if response_info["status"] ~= nil then
            if path_spec["responses"][response_info["status"]] ~= nil then
              validate_response(request_info, response_info, path_spec["responses"][response_info["status"]])
            elseif path_spec["responses"]["default"] ~= nil then
              validate_response(request_info, response_info, path_spec["responses"]["default"])
            else
              table.insert(response_info["errors"], "Invalid response code")
            end
          else
            table.insert(response_info["warnings"], "No response code")
          end
        end
        if path_spec["summary"] ~= nil then
          request_info["summary"] = path_spec["summary"]
        end
        if path_spec["document"] ~= nil then
          request_info["spec"] = path_spec["document"]
        end
        if path_spec["operation"] ~= nil then
          request_info["operation"] = path_spec["operation"]
        elseif callback then
          request_info["operation"] = "Callback " .. callback["key"]
        end
        if path_spec["description"] ~= nil then
          request_info["description"] = path_spec["description"]
        end
      else
        table.insert(request_info["warnings"], "Path not found in OpenAPI specification")
      end
      request_info["parsed"] = true
    end

    if request_info["headers_frame"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_headers_frame, request_info["headers_frame"]):set_generated()
    end
    if request_info["callback_registration"] ~= nil then
      request_subtree:add(openapi_proto.fields.callback_registration, request_info["callback_registration"]):set_generated()
    end
    if request_info["callbacks"] ~= nil then
      for i, v in pairs(request_info["callbacks"]) do
        request_subtree:add(openapi_proto.fields.callback, v):set_generated()
      end
    end
    if request_info["data_frame"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_data_frame, request_info["data_frame"]):set_generated()
    end
    if request_info["path"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_path, request_info["path"]):set_generated()
    end
    if request_info["path_valid"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_path_valid, request_info["path_valid"]):set_generated()
    end
    if request_info["method"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_method, request_info["method"]):set_generated()
    end
    if request_info["data"] ~= nil then
      request_subtree:add(openapi_proto.fields.request_data, request_info["data"]):set_generated()
    end

    if response_info["headers_frame"] ~= nil then
      response_subtree:add(openapi_proto.fields.request_headers_frame, response_info["headers_frame"]):set_generated()
    end
    if response_info["data_frame"] ~= nil then
      response_subtree:add(openapi_proto.fields.request_data_frame, response_info["data_frame"]):set_generated()
    end
    if response_info["data"] ~= nil then
      response_subtree:add(openapi_proto.fields.response_data, response_info["data"]):set_generated()
    end
    if response_info["status"] ~= nil then
      response_subtree:add(openapi_proto.fields.response_status, response_info["status"]):set_generated()
    end
    if response_info["location"] ~= nil then
      response_subtree:add(openapi_proto.fields.response_location, response_info["location"]):set_generated()
    end
  else

    local http2_headers = f_http2_headers()
    if http2_headers ~= nil then
      stream_info["headers_frame"] = pinfo.number

      local http2_headers_method = f_http2_headers_method()
      if http2_headers_method then
        stream_info["method"] = tostring(http2_headers_method.value)
      end

      local http2_headers_host = f_http2_headers_host()
      if http2_headers_host then
        stream_info["host"] = tostring(http2_headers_host.value)
      end

      local http2_headers_path = f_http2_headers_path()
      if http2_headers_path then
        stream_info["path"] = tostring(http2_headers_path.value)
      end

      local http2_headers_content_type = f_http2_headers_content_type()
      if http2_headers_content_type then
        stream_info["content_type"] = tostring(http2_headers_content_type.value)
      end

      local http2_headers_location = f_http2_headers_location()
      if http2_headers_location then
        stream_info["location"] = tostring(http2_headers_location.value)
      end

      local http2_headers_status = f_http2_headers_status()
      if http2_headers_status then
        stream_info["status"] = tostring(http2_headers_status.value)
        stream_info["headers_frame"] = pinfo.number
      end
    end

    local http2_data_data = f_http2_data_data()
    if http2_data_data then
      if request_info["method"] == nil then
        request_info["method"] = "PUT"
      end
      local data = hexdecode(tostring(http2_data_data.value))

      if stream_info["content_type"] == nil or stream_info["content_type"] == "application/json" then
        stream_info["content_type"] = "application/json" -- TODO: figure out how to better handle this fallback case
        DissectorTable.get("http2.streamid"):add(http2_streamid.value, json_dissector)
      end
      stream_info["data"] = data
      stream_info["data_length"] = tonumber(f_http2_length().value)
      stream_info["data_frame"] = pinfo.number
    end
  end
end


local http2_dissector = Dissector.get("http2")
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(7777, http2_dissector)
tcp_table:add(8080, http2_dissector)

register_postdissector(openapi_proto)
