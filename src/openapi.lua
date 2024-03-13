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
openapi_proto.fields.request_content_type = ProtoField.string("openapi.request.content_type", "Request Content-Type")
openapi_proto.fields.request_path = ProtoField.string("openapi.request.path", "Request Path")
openapi_proto.fields.request_path_valid = ProtoField.bool("openapi.request.path_valid", "Request Path Valid")
openapi_proto.fields.request_valid = ProtoField.string("openapi.request.valid", "Request Validated")
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
openapi_proto.fields.response_content_type = ProtoField.string("openapi.response.content_type", "Response Content-Type")
openapi_proto.fields.response_location = ProtoField.string("openapi.response.location", "Response Redirect Location")
openapi_proto.fields.response_valid = ProtoField.string("openapi.response.valid", "Response Validated")
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
    set_color_filter_slot(8, "openapi.warning || openapi.request.warning || openapi.response.warning")
  end
end

function hexdecode(hex)
  return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

local validators = {}
validators["application/json"] = json_validator.validate_raw_json

function parse_multipart_message(data, content_type, content_spec)
  local parts = {}
  if string.sub(content_type, 1, 17) == "multipart/related" then
    -- TODO: this could probably be solved better...
    local content_type_semicol = string.find(content_type, ";")
    local boundary = string.sub(content_type, content_type_semicol)
    local boundary = string.sub(boundary, string.find(boundary, "boundary=") + 9, -1)
    if string.sub(boundary, 1, 1) == '"' or string.sub(boundary, 1, 1) == "'" then
      boundary = string.sub(boundary, 2, -2)
    end
    boundary = "--" .. boundary

    local part_idx = 0
    local part_header_search = false
    while true do
      if string.len(data) == (string.len(boundary) + 4) then break end
      if string.sub(data, 1, string.len(boundary)) == boundary then
        part_idx = part_idx + 1
        parts[part_idx] = {}
        parts[part_idx]["headers_raw"] = ""
        parts[part_idx]["headers"] = {}
        parts[part_idx]["data"] = ""
        parts[part_idx]["schema"] = nil
        part_header_search = true
        data = string.sub(data, string.len(boundary) + 3)
      end
      if part_header_search then
        if string.sub(data, 1, 4) == "\r\n\r\n" then
          parts[part_idx]["headers_raw"] = parts[part_idx]["headers_raw"] .. "\r\n"
          part_header_search = false
          while string.find(parts[part_idx]["headers_raw"], "\r\n") do
            local header = string.sub(parts[part_idx]["headers_raw"], 1, string.find(parts[part_idx]["headers_raw"], "\r\n") - 1)
            parts[part_idx]["headers_raw"] = string.sub(parts[part_idx]["headers_raw"], string.find(parts[part_idx]["headers_raw"], "\r\n") + 2)
            local header_name = string.sub(header, 1, string.find(header, ": ") - 1)
            local header_value = string.sub(header, string.find(header, ": ") + 2)
            parts[part_idx]["headers"][header_name] = header_value
          end
          if parts[part_idx]["headers"]["Content-Type"] then
            local ct_encodings = openapi_get_value(content_spec["multipart/related"], "encoding")
            for ct_enc_name, ct_enc in pairs(ct_encodings) do
              local ct_mp_schema = openapi_get_value(content_spec["multipart/related"], "schema")
              local ct_mp_schema_properties = openapi_get_value(ct_mp_schema, "properties")
              local ct_schema = openapi_get_value(ct_mp_schema_properties, ct_enc_name)
              if ct_enc["contentType"] == parts[part_idx]["headers"]["Content-Type"] then
                parts[part_idx]["schema"] = ct_schema
              end
            end
          end
          data = string.sub(data, 4)
        else
          parts[part_idx]["headers_raw"] = parts[part_idx]["headers_raw"] .. string.sub(data, 1, 1)
        end
      else
        parts[part_idx]["data"] = parts[part_idx]["data"] .. string.sub(data, 1, 1)
      end
      data = string.sub(data, 2)
      if data == "" then
        break
      end
    end
  else
    parts[1] = {}
    parts[1]["data"] = data
    parts[1]["headers"] = {}
    parts[1]["headers"]["Content-Type"] = content_type
    local part_content_spec = openapi_get_value(content_spec, content_type)
    if part_content_spec then
      parts[1]["schema"] = openapi_get_value(part_content_spec, "schema")
    else
      parts[1]["schema"] = nil
    end
  end
  return parts
end

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

  if request_info["content_type"] == nil then
    for spec_content_type, spec_table in pairs(content_spec) do
      request_info["content_type"] = spec_content_type
    end
  end

  -- handling of mixed containers with json and other data
  local parts = parse_multipart_message(request_info["data"], request_info["content_type"], content_spec)

  for i, part in pairs(parts) do
    -- workaround for missing headers due to http2 compression
    if part["headers"]["Content-Type"] == nil then
      part["headers"]["Content-Type"] = "application/json"
    end

    if validators[part["headers"]["Content-Type"]] == nil then
      if rex_pcre2.match(part["headers"]["Content-Type"], "^application/.*json") then
        validators[part["headers"]["Content-Type"]] = validators["application/json"]
      end
    end

    if validators[part["headers"]["Content-Type"]] ~= nil and part["schema"] ~= nil then
      local errors = {}
      local extra_info = {}
      extra_info["type"] = "request"
      extra_info["callback_map"] = callback_map
      extra_info["callback_spec"] = callback_spec
      local valid = validators[part["headers"]["Content-Type"]](part["data"], part["schema"], "root", errors, extra_info)
      local out = ""
      if valid then
        for _, err in pairs(errors) do
          table.insert(request_info["warnings"], "Validation: " .. err)
        end
      else
        for _, err in pairs(errors) do
          table.insert(request_info["errors"], "Validation: " .. err)
        end
      end
      request_info["valid"] = valid
      return valid
    else
      table.insert(request_info["warnings"], "No validator was applied to this request (probably because of missing or weird content type header)")
    end
  end
end

function validate_response(request_info, response_info, response_spec)
  local content_spec = openapi_get_value(response_spec, "content")
  if content_spec == nil then return end

  if response_info["content_type"] == nil then
    for spec_content_type, spec_table in pairs(content_spec) do
      response_info["content_type"] = spec_content_type
    end
  end

  if validators[response_info["content_type"]] == nil then
    if rex_pcre2.match(response_info["content_type"], "^application/.*json") then
      validators[response_info["content_type"]] = validators["application/json"]
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
    if valid then
      for _, err in pairs(errors) do
        table.insert(response_info["warnings"], "Validation: " .. err)
      end
    else
      for _, err in pairs(errors) do
        table.insert(response_info["errors"], "Validation: " .. err)
      end
    end
    response_info["valid"] = valid
    return valid
  else
    table.insert(response_info["warnings"], "No validator was applied to this response (probably because of missing or weird content type header)")
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
  local is_http2 = f_http2_streamid()
  if not is_http2 then return end

  -- workaround to load field data before packet is marked as visited
  f_http2_data_data()
  f_http2_length()
  f_http2_headers()
  f_http2_headers_method()
  f_http2_headers_host()
  f_http2_headers_path()
  f_http2_headers_status()
  f_http2_headers_content_type()
  f_http2_headers_location()
  f_http2_flags_end_stream()
  f_http2_type()

  -- collect information from dissection tree
  local http2_transfers = {}
  local http2_transfer_idx = 0
  local fields = { all_field_infos() }
  for f_i, f_info in pairs(fields) do
    if string.sub(f_info.name, 1, 5) == "http2" then
      if f_info.name == "http2" then
        http2_transfer_idx = http2_transfer_idx + 1
        http2_transfers[http2_transfer_idx] = {}
        http2_transfers[http2_transfer_idx]["headers"] = {}
        http2_transfers[http2_transfer_idx]["data"] = nil
        http2_transfers[http2_transfer_idx]["streamid"] = nil
        http2_transfers[http2_transfer_idx]["type"] = nil
        http2_transfers[http2_transfer_idx]["length"] = 0
        http2_transfers[http2_transfer_idx]["end_stream"] = false
      elseif f_info.name == "http2.length" then
        http2_transfers[http2_transfer_idx]["length"] = tonumber(f_info.value)
      elseif f_info.name == "http2.type" then
        http2_transfers[http2_transfer_idx]["type"] = tonumber(f_info.value)
      elseif f_info.name == "http2.flags.end_stream" then
        if tostring(f_info.value) == "true" then
          http2_transfers[http2_transfer_idx]["end_stream"] = true
        end
      elseif f_info.name == "http2.data.data" then
        http2_transfers[http2_transfer_idx]["data"] = hexdecode(tostring(f_info.value))
      elseif f_info.name == "http2.streamid" then
        http2_transfers[http2_transfer_idx]["streamid"] = f_info.value
      elseif string.sub(f_info.name, 1, 14) == "http2.headers." then
        http2_transfers[http2_transfer_idx]["headers"][string.sub(f_info.name, 15)] = f_info.value
      end
    end
  end

  -- parse collected information
  local packet_description = ""
  for http2_transfer_idx, http2_transfer in pairs(http2_transfers) do
    -- ignore everything but headers and data
    if http2_transfer["type"] ~= 0 and http2_transfer["type"] ~= 1 then goto http2_transfers_loop_end end

    local streamid = string.format("%s/%s", tcp_stream, http2_transfer["streamid"])
    if stream_map[streamid] == nil then
      stream_map[streamid] = {}
      stream_map[streamid]["request"] = {}
      stream_map[streamid]["response"] = {}
    end
    if substreamnums[streamid] == nil then
      substreamnums[streamid] = 0
    end

    pinfo_subindex = string.format("%s/%s", pinfo.number, http2_transfer_idx)
    if not pinfo.visited then
      packet_map[pinfo_subindex] = substreamnums[streamid]
      if http2_transfer["end_stream"] then
        substreamnums[streamid] = substreamnums[streamid] + 1
      end
    end

    if stream_map[streamid][packet_map[pinfo_subindex]] == nil then
      stream_map[streamid][packet_map[pinfo_subindex]] = {}
    end

    local stream_info = stream_map[streamid][packet_map[pinfo_subindex]]
    local packet_type = nil
    local request_info = nil
    local response_info = nil
    if packet_map[pinfo_subindex] % 2 == 0 then
      packet_type = "request"
      request_info = stream_map[streamid][packet_map[pinfo_subindex]]
      response_info = stream_map[streamid][packet_map[pinfo_subindex]+1]
    else
      packet_type = "response"
      request_info = stream_map[streamid][packet_map[pinfo_subindex]-1]
      response_info = stream_map[streamid][packet_map[pinfo_subindex]]
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
      local short_description = "OpenAPI"
      local pinfo_description = ""
      local operation_description = ""
      if request_info["operation"] then
        operation_description = request_info["operation"]
      elseif request_info["summary"] then
        operation_description = string.sub(request_info["summary"], 1, 20)
      end

      if packet_type == "request" then
        if operation_description ~= "" then
          short_description = string.format("OpenAPI Request (%s)", operation_description)
          if http2_transfer["type"] == 1 then
            pinfo_description = string.format("Req-Hdr (%s)", operation_description)
          else
            pinfo_description = string.format("Req-Dat (%s)", operation_description)
          end
        else
          short_description = string.format("OpenAPI Request")
          if http2_transfer["type"] == 1 then
            pinfo_description = string.format("Req-Hdr")
          else
            pinfo_description = string.format("Req-Dat")
          end
        end
      else
        if operation_description ~= "" then
          short_description = string.format("OpenAPI Response (%s)", operation_description)
          if http2_transfer["type"] == 1 then
            pinfo_description = string.format("Res-Hdr (%s)", operation_description)
          else
            pinfo_description = string.format("Res-Dat (%s)", operation_description)
          end
        else
          short_description = string.format("OpenAPI Response")
          if http2_transfer["type"] == 1 then
            pinfo_description = string.format("Res-Hdr")
          else
            pinfo_description = string.format("Res-Dat")
          end
        end
      end

      -- TODO: make info more readable, especially for packets with multiple http2/openapi segments
      if not string.find(tostring(pinfo.cols.protocol), "OpenAPI") then
        pinfo.cols.protocol = tostring(pinfo.cols.protocol) .. "/OpenAPI"
      end

      if packet_description == "" then
        packet_description = "OpenAPI: " .. pinfo_description
      else
        packet_description = packet_description .. ", " .. pinfo_description
      end

      -- skip tree rendering if headers and data are contained in the same packet (avoids duplicate identical tree in overview)
      if packet_type == "request" and tonumber(request_info["headers_frame"]) == tonumber(request_info["data_frame"]) and http2_transfer["type"] == 0 then
        goto http2_transfers_loop_end
      elseif packet_type == "response" and tonumber(response_info["headers_frame"]) == tonumber(response_info["data_frame"]) and http2_transfer["type"] == 0 then
        goto http2_transfers_loop_end
      end

      local toptree
      toptree = tree:add(openapi_proto, short_description)
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

      subtree:add(openapi_proto.fields.substream_id, packet_map[pinfo_subindex]):set_generated()
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
          if path_spec["operationId"] ~= nil then
            request_info["operation"] = path_spec["operationId"]
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
      if request_info["content_type"] ~= nil then
        request_subtree:add(openapi_proto.fields.request_content_type, request_info["content_type"]):set_generated()
      end
      if request_info["valid"] ~= nil then
        if request_info["valid"] then
          request_subtree:add(openapi_proto.fields.request_valid, "Yes"):set_generated()
        else
          request_subtree:add(openapi_proto.fields.request_valid, "No"):set_generated()
        end
      end

      if response_info["headers_frame"] ~= nil then
        response_subtree:add(openapi_proto.fields.response_headers_frame, response_info["headers_frame"]):set_generated()
      end
      if response_info["data_frame"] ~= nil then
        response_subtree:add(openapi_proto.fields.response_data_frame, response_info["data_frame"]):set_generated()
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
      if response_info["content_type"] ~= nil then
        response_subtree:add(openapi_proto.fields.response_content_type, response_info["content_type"]):set_generated()
      end
      if response_info["valid"] ~= nil then
        if response_info["valid"] then
          response_subtree:add(openapi_proto.fields.response_valid, "Yes"):set_generated()
        else
          response_subtree:add(openapi_proto.fields.response_valid, "No"):set_generated()
        end
      end
    else
      if http2_transfer["type"] == 1 then
        stream_info["headers_frame"] = pinfo.number

        if http2_transfer["headers"]["method"] then
          stream_info["method"] = tostring(http2_transfer["headers"]["method"])
        end

        if http2_transfer["headers"]["host"] then
          stream_info["host"] = tostring(http2_transfer["headers"]["host"])
        end

        if http2_transfer["headers"]["path"] then
          stream_info["path"] = tostring(http2_transfer["headers"]["path"])
        end

        if http2_transfer["headers"]["content_type"] then
          stream_info["content_type"] = tostring(http2_transfer["headers"]["content_type"])
        end

        if http2_transfer["headers"]["location"] then
          stream_info["location"] = tostring(http2_transfer["headers"]["location"])
        end

        if http2_transfer["headers"]["status"] then
          stream_info["status"] = tostring(http2_transfer["headers"]["status"])
        end
      end

      if http2_transfer["data"] then
        if request_info["method"] == nil then
          request_info["method"] = "PUT"
        end
        local data = http2_transfer["data"]

        if stream_info["content_type"] == "application/json" or string.sub(data, 1, 1) == "{" then
          DissectorTable.get("http2.streamid"):add(http2_transfer["streamid"], json_dissector)
        end
        stream_info["data"] = data
        stream_info["data_length"] = tonumber(http2_transfer["length"])
        stream_info["data_frame"] = pinfo.number
      end
    end
    ::http2_transfers_loop_end::
  end
  if packet_description ~= "" then
    pinfo.cols.info = packet_description
  end
end


local http2_dissector = Dissector.get("http2")
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(7777, http2_dissector)
tcp_table:add(8080, http2_dissector)

register_postdissector(openapi_proto)
