openapi_spec = {}

local json = require "json"

local DEBUG = false

function debug_print(...)
  if DEBUG then
    io.stderr:write(...)
    io.stderr:write("\n")
  end
end

-- TODO: better handling of callback paths
function register_callbacks(content, path, extra_infos)
  local tmp_path = string.gsub(path, "{[^}]*}", "")
  tmp_path = string.gsub(tmp_path, "^root", "{$request.body#")
  tmp_path = string.gsub(tmp_path, "]", "")
  tmp_path = string.gsub(tmp_path, "%[", "/")
  tmp_path = string.gsub(tmp_path, "$", "}")

  if extra_infos["callback_spec"][tmp_path] then
    extra_infos["callback_map"][content] = extra_infos["callback_spec"][tmp_path]
  end
end

function validate_json_string(content, schema, path, errors, extra_infos)
  register_callbacks(content, path, extra_infos)

  local schema_pattern = openapi_get_value(schema, "pattern")
  if schema_pattern ~= nil then
    if rex_pcre2.match(content, schema_pattern) ~= nil then
      return true
    else
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="string.pattern", path=path, details=schema_pattern}))
      else
        table.insert(errors, "String at " .. path .. " does not match given pattern " .. schema_pattern)
      end
      return false
    end
  end

  if type(content) ~= "string" then
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="string.wrongtype", path=path}))
    else
      table.insert(errors, "Element at " .. string .. " doesn't seem to be a string.")
    end
    return false
  end

  return true
end

function validate_json_boolean(content, schema, path, errors, extra_infos)
  if type(content) == "boolean" then
    return true
  else
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="bool.wrongtype", path=path}))
    else
      table.insert(errors, "Element at " .. path .. " doesn't seem to be boolean.")
    end
    return false
  end
end

function validate_json_number(content, schema, path, errors, extra_infos)
  -- check for number type
  if type(content) ~= "number" then
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="number.wrongtype", path=path}))
    else
      table.insert(errors, "Element at " .. path .. " doesn't seem to be a number.")
    end
    return false
  end

  -- test minimum boundary
  local schema_exclusiveMinimum = openapi_get_value(schema, "exclusiveMinimum")
  local schema_minimum = openapi_get_value(schema, "minimum")

  if schema_exclusiveMinimum then
    if schema_minimum ~= nil and not (content > schema_minimum) then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="number.boundary.minimum", path=path, details=schema_minimum}))
      else
        table.insert(errors, "Number at " .. path .. " is outside of minimum boundary (" .. schema_minimum .. ")")
      end
      return false
    end
  else
    if schema_minimum ~= nil and not (content >= schema_minimum) then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="number.boundary.minimum", path=path, details=schema_minimum}))
      else
        table.insert(errors, "Number at " .. path .. " is outside of minimum boundary (" .. schema_minimum .. ")")
      end
      return false
    end
  end

  -- test maximum boundary
  local schema_exclusiveMaximum = openapi_get_value(schema, "exclusiveMaximum")
  local schema_maximum = openapi_get_value(schema, "maximum")

  if schema_exclusiveMaximum then
    if schema_maximum ~= nil and not (content < schema_maximum) then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="number.boundary.maximum", path=path, details=schema_maximum}))
      else
        table.insert(errors, "Number at " .. path .. " is outside of maximum boundary (" .. schema_maximum .. ")")
      end
      return false
    end
  else
    if schema_maximum ~= nil and not (content <= schema_maximum) then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="number.boundary.maximum", path=path, details=schema_maximum}))
      else
        table.insert(errors, "Number at " .. path .. " is outside of maximum boundary (" .. schema_maximum .. ")")
      end
      return false
    end
  end

  -- test for multiple of certain value
  local schema_multipleOf = openapi_get_value(schema, "multipleOf")

  if schema_multipleOf ~= nil then
    if (content % schema_multipleOf) ~= 0.0 then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="number.multipleof", path=path, details=schema_multipleOf}))
      else
        table.insert(errors, "Number at " .. path .. " violates defined multipleOf policy (" .. schema_multipleOf .. ")")
      end
      return false
    end
  end

  return true
end

function validate_json_array(content, schema, path, errors, extra_infos)
  local failed = false

  if type(content) ~= "table" then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="array.wrongtype", path=path, details="non-table-structure"}))
      else
        table.insert(errors, "Element at " .. path .. " doesn't seem to be an array (non-table data structure).")
      end
      return false
  end
  local num_items = 0
  for k in pairs(content) do
    num_items = num_items + 1
    if tonumber(k) == nil then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="array.wrongtype", path=path, details="non-numeric-index"}))
      else
        table.insert(errors, "Element at " .. path .. " doesn't seem to be an array (non-numeric index).")
      end
      return false
    end
  end
  if num_items ~= #content then
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="array.wrongtype", path=path, details="non-sequential-index"}))
    else
      table.insert(errors, "Element at " .. path .. " doesn't seem to be an array.")
    end
    return false
  end

  -- check minimum number of items
  local schema_minItems = openapi_get_value(schema, "minItems")
  if schema_minItems ~= nil then
    if num_items < schema_minItems then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="array.minitems", path=path, details=schema_minItems}))
      else
        table.insert(errors, "Array at " .. path .. " contains fewer items than allowed (min: " .. schema_minItems .. ")")
      end
      failed = true
    end
  end

  -- check maximum number of items
  local schema_maxItems = openapi_get_value(schema, "maxItems")
  if schema_maxItems ~= nil then
    if num_items > schema_maxItems then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="array.maxitems", path=path, details=schema_maxItems}))
      else
        table.insert(errors, "Array at " .. path .. " contains more items than allowed (max: " .. schema_maxItems .. ")")
      end
      failed = true
    end
  end

  -- check for unique items
  local schema_uniqueItems = openapi_get_value(schema, "uniqueItems")
  if schema_uniqueItems then
    local hashes = {}
    for k in pairs(content) do
      local hash = json.encode(content[k])

      local hashfound = false
      for _, v in pairs(hashes) do
        if v == hash then
          hashfound = true
          break
        end
      end

      if hashfound then
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="array.nonunique", path=path}))
          else
            table.insert(errors, "Array at " .. path .. " contains non-unique items.")
          end
          failed = true
          break
      end
      table.insert(hashes, hash)
    end
  end

  -- check item validity
  for k in pairs(content) do
    if not validate_json(content[k], openapi_get_value(schema, "items"), path .. "[" .. k .. "]", errors, extra_infos) then
      failed = true
    end
  end

  return (not failed)
end

function validate_json_object(content, schema, path, errors, extra_infos)
  if type(content) ~= "table" then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="object.wrongtype", path=path, details="non-table-structure"}))
      else
        table.insert(errors, "Element at " .. path .. " doesn't seem to be an object (non-table data structure).")
      end
      return false
  end

  local valid = true

  local schema_required = openapi_get_value(schema, "required")
  local schema_properties = openapi_get_value(schema, "properties")

  local subschemas = {}

  -- check for required properties
  if schema_required ~= nil then
    for _, key in pairs(schema_required) do
      if subschemas[key] == nil then
        subschemas[key] = openapi_get_value(schema_properties, key)
      end
      if content[key] == nil then
        if openapi_get_value(subschemas[key], "readOnly") and extra_infos["type"] == "request" then
          -- do nothing
        elseif openapi_get_value(subschemas[key], "writeOnly") and extra_infos["type"] == "response" then
          -- do nothing
        else
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="object.missing_argument", path=path, details=key}))
          else
            table.insert(errors, "Missing required argument '" .. key .. "' at " .. path)
          end
          valid = false
        end
      else
        if openapi_get_value(subschemas[key], "readOnly") and extra_infos["type"] == "request" then
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="object.send_readonly", path=path, details=key}))
          else
            table.insert(errors, "Sending readOnly argument '" .. key .."' in request at " .. path)
          end
          valid = false
        elseif openapi_get_value(subschemas[key], "writeOnly") and extra_infos["type"] == "response" then
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="object.receive_writeonly", path=path, details=key}))
          else
            table.insert(errors, "Sending writeOnly argument '" .. key .."' in response at " .. path)
          end
          valid = false
        end
      end
    end
  end

  -- check validity of properties
  if schema_properties ~= nil then
    for key, subschema in pairs(schema_properties) do
      if content[key] ~= nil then
        if not validate_json(content[key], subschema, path .. "[" .. key .. "]", errors, extra_infos) then
          -- table.insert(errors, "Object argument '" .. key .. "' failed to validate at " .. path)
          valid = false
        end
      end
    end
  end

  -- check for forbidden properties
  local _not = openapi_get_value(schema, "not")
  if _not ~= nil then
    local not_type = openapi_get_value(_not, "type")
    if not_type == nil or not_type == "object" then
      local not_required = openapi_get_value(_not, "required")
      if not_required ~= nil then
        for _, key in pairs(not_required) do
          if content[key] ~= nil then
            if extra_infos["machine_readable"] then
              table.insert(errors, json.encode({error="object.forbidden_key", path=path, details=key}))
            else
              table.insert(errors, "Object contains forbidden argument '" .. key .. "' at " .. path)
            end
            valid = false
          end
        end
      end

      local not_properties = openapi_get_value(_not, "properties")
      if not_properties ~= nil then
        for key, subschema in pairs(not_properties) do
          local suberrors = {}
          if validate_json(content[key], subschema, path .. "[" .. key .. "]", suberrors, extra_infos) then
            if extra_infos["machine_readable"] then
              table.insert(errors, json.encode({error="object.unwanted_properties", path=path, details=key}))
            else
              table.insert(errors, "Object argument '" .. key .. "' matches unwanted properties at " .. path)
            end
            valid = false
          end
        end
      end
    else
      -- TODO
    end
  end

  local num_properties = 0
  for _ in pairs(content) do
    num_properties = num_properties + 1
  end

  -- check minimum number of properties
  local schema_minProperties = openapi_get_value(schema, "minProperties")
  if schema_minProperties ~= nil then
    if num_properties < schema_minProperties then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="object.minproperties", path=path, details=schema_minProperties}))
      else
        table.insert(errors, "Element at " .. path .. " contains fewer properties than allowed (min: " .. schema_minProperties .. ")")
      end
      valid = false
    end
  end

  -- check maximum number of properties
  local schema_maxProperties = openapi_get_value(schema, "maxProperties")
  if schema_maxProperties ~= nil then
    if num_properties > schema_maxProperties then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="object.maxproperties", path=path, details=schema_maxProperties}))
      else
        table.insert(errors, "Element at " .. path .. " contains more properties than allowed (max: " .. schema_maxProperties .. ")")
      end
      valid = false
    end
  end

  -- check for additional properties
  local schema_additional_properties = openapi_get_value(schema, "additionalProperties")
  if schema_additional_properties ~= nil then
    -- TODO: this seems wrong?
    for key, subcontent in pairs(content) do
      if schema_additional_properties == false and schema_properties[key] == nil then
        if extra_infos["machine_readable"] then
          table.insert(errors, json.encode({error="object.disallowed_additional_property", path=path, details=key}))
        else
          table.insert(errors, "Disallowed additional property '" .. key .. "' at " .. path)
        end
      elseif type(schema_additional_properties) == "table" then
        if not validate_json(content[key], schema_additional_properties, path .. "[" .. key .. "]", errors, extra_infos) then
          valid = false
        end
      end
    end
  end
  return valid
end

function validate_json_integer(content, schema, path, errors, extra_infos)
  if not validate_json_number(content, schema, path, errors, extra_infos) then
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="integer.wrongtype", path=path, details="not-a-number"}))
    else
      table.insert(errors, "Element at " .. path .. " doesn't seem to be a number, so it also can't be an integer.")
    end
    return false
  elseif math.floor(content) ~= content then
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="integer.wrongtype", path=path, details="non-zero-decimal"}))
    else
      table.insert(errors, "Element at " .. path .. " doesn't seem to be an integer.")
    end
    return false
  else
    return true
  end
end

function validate_json_null(content, schema, path, errors, extra_infos)
  if content == nil then
    return true
  else
    return false
  end
end

function validate_multiple(content, schema, mtype, path, suberrors, extra_infos)
  debug_print("Entering " .. mtype .. " validation at " .. path)
  local schema_discriminator = openapi_get_value(schema, "discriminator")
  -- Handle oneOf situations with defined discriminator value
  if mtype == "oneOf" and schema_discriminator then
    local propname = openapi_get_value(schema_discriminator, "propertyName")
    local discriminator_value = content[propname]

    if discriminator_value == nil then
      if extra_infos["machine_readable"] then
        table.insert(suberrors, json.encode({error="oneof.discriminator_missing", path=path, subpath="[" .. propname .. "]"}))
      else
        table.insert(suberrors, "Discriminator " .. path .. "[" .. propname .. "] missing, oneOf validation can't continue")
      end
      debug_print("Left " .. mtype .. " validation at " .. path .. " (fail? discriminator '" .. propname .. "' missing in object)")
      return 0, 1
    end

    local path = path .. "{" .. tostring(propname) .. "=" .. tostring(discriminator_value) .. "}"
    local schema_discr_mapping = openapi_get_value(schema_discriminator, "mapping")
    local subschema = openapi_resolve_reference(schema_discr_mapping[discriminator_value])
    subschema["parent"] = schema

    suberrors[discriminator_value] = {}
    local retval = validate_json(content, subschema, path, suberrors[discriminator_value], extra_infos)
    if retval then
      debug_print("Left " .. mtype .. " validation at " .. path .. " (success?)")
      return 1, 0
    else
      debug_print("Left " .. mtype .. " validation at " .. path .. " (fail?)")
      return 0, 1
    end
  -- Handle all other oneOf/anyOf/allOf situations
  -- This basically loops through all defined subschemas and keeps count of
  -- valid and invalid validations. Errors are logged into a separate suberrors
  -- list that can be printed outside of this function if the oneOf/anyOf/allOf
  -- check fails.
  else
    local valid = 0
    local invalid = 0
    local valids = {}
    for i, subschema in pairs(openapi_get_value(schema, mtype)) do
      -- parent schema gets stored as a lot of times data types or other
      -- important information is not available inside of the defined subschema
      subschema["parent"] = schema

      if validate_json(content, subschema, path .. "{sub:" .. i .. "}", suberrors, extra_infos) then
        local subschema_description = openapi_get_value(subschema, "description")
        if subschema_description ~= nil then
          table.insert(valids, '"' .. subschema_description .. '"')
        else
          table.insert(valids, "Index " .. i)
        end
        valid = valid + 1
      else
        invalid = invalid + 1
      end
    end
    return valid, invalid, valids
  end
end

local json_validators = {}
json_validators["object"] = validate_json_object
json_validators["array"] = validate_json_array
json_validators["number"] = validate_json_number
json_validators["integer"] = validate_json_integer
json_validators["string"] = validate_json_string
json_validators["null"] = validate_json_null
json_validators["boolean"] = validate_json_boolean

function validate_json(content, schema, path, errors, extra_infos)
  local schema_type = openapi_get_value(schema, "type")

  local schema_oneof = openapi_get_value(schema, "oneOf")
  local schema_anyof = openapi_get_value(schema, "anyOf")
  local schema_allof = openapi_get_value(schema, "allOf")
  local schema_enum = openapi_get_value(schema, "enum")

  -- TODO: handle more "not" parameters
  local _not = openapi_get_value(schema, "not")
  if _not ~= nil then
    debug_print("Unhandled 'not': " .. path)
  end

  local validator_found = false

  debug_print(string.format("<VALIDATE %s>", schema_type))
  for k, v in pairs(schema) do
    debug_print(string.format("schema[%s] = %s", k, v))
  end
  if schema_type == nil then
    debug_print(string.format("schema[oneOf] = %s", schema_oneof))
    debug_print(string.format("schema[anyOf] = %s", schema_anyof))
    debug_print(string.format("schema[allOf] = %s", schema_allof))
  end
  if type(content) == "table" then
    for k, v in pairs(content) do
      debug_print(string.format("content[k] = %s", k, v))
    end
  else
    debug_print(string.format("content = %s", content))
  end
  debug_print("<START>")

  local schema_nullable = openapi_get_value(schema, "nullable")
  local schema_enum = openapi_get_value(schema, "enum")

  -- check for nullable null
  if content == nil and schema_nullable and schema_enum == nil then
    return true
  end

  -- check for enum
  if schema_enum ~= nil then
    for _, val in pairs(schema_enum) do
      if val == content then
        return true
      end
    end
    if extra_infos["machine_readable"] then
      table.insert(errors, json.encode({error="enum.nomatch", path=path}))
    else
      table.insert(errors, "Value at " .. path .. " does not match any entry in enumeration")
    end
    return false
  end

  -- check for oneOf/anyOf/allOf
  if schema_oneof then
    validator_found = true
    local suberrors = {}
    local valid, invalid, valids = validate_multiple(content, schema, "oneOf", path, suberrors, extra_infos)
    if valid ~= 1 then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="oneof.criterium_failed", path=path, details={valid=valid, invalid=invalid}}))
      else
        table.insert(errors, "oneOf criterium failed on " .. path .. ": " .. valid .. " valid, " .. invalid .. " invalid")
      end
      if valid > 1 then
        if extra_infos["machine_readable"] then
          table.insert(errors, json.encode({error="oneof.multiple_valid", path=path, details=valids}))
        else
          table.insert(errors, ">> Multiple valid in oneOf criterium: " .. table.concat(valids, ", "))
        end
      else
        for k, v in pairs(suberrors) do
          if type(v) == "table" then
            if not extra_infos["machine_readable"] then
              table.insert(errors, ">> # " .. k)
            end
            for _, err in pairs(v) do
              if extra_infos["machine_readable"] then
                table.insert(errors, json.encode({error="oneof.suberror", path=path, key=k, suberr=json.decode(err)}))
              else
                table.insert(errors, ">> " .. err)
              end
            end
          else
            if extra_infos["machine_readable"] then
              table.insert(errors, json.encode({error="oneof.suberror", path=path, suberr=json.decode(v)}))
            else
              table.insert(errors, ">> " .. v)
            end
          end
        end
      end
      return false
    end
  elseif schema_anyof then
    validator_found = true
    local suberrors = {}
    local valid, invalid = validate_multiple(content, schema, "anyOf", path, suberrors, extra_infos)
    if valid == 0 then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="anyof.criterium_failed", path=path, details={valid=valid, invalid=invalid}}))
      else
        table.insert(errors, "anyOf criterium failed on " .. path .. ": " .. valid .. " valid, " .. invalid .. " invalid")
      end
      for k, v in pairs(suberrors) do
        if type(v) == "table" then
          if not extra_infos["machine_readable"] then
            table.insert(errors, ">> # " .. k)
          end
          for _, err in pairs(v) do
            if extra_infos["machine_readable"] then
              table.insert(errors, json.encode({error="anyof.suberror", path=path, key=k, suberr=json.decode(err)}))
            else
              table.insert(errors, ">> " .. err)
            end
          end
        else
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="anyof.suberror", path=path, suberr=json.decode(v)}))
          else
            table.insert(errors, ">> " .. v)
          end
        end
      end
      return false
    end
  elseif schema_allof then
    validator_found = true
    local suberrors = {}
    local valid, invalid = validate_multiple(content, schema, "allOf", path, suberrors, extra_infos)
    if invalid > 0 then
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="allof.criterium_failed", path=path, details={valid=valid, invalid=invalid}}))
      else
        table.insert(errors, "allOf criterium failed on " .. path .. ": " .. valid .. " valid, " .. invalid .. " invalid")
      end
      for k, v in pairs(suberrors) do
        if type(v) == "table" then
          if not extra_infos["machine_readable"] then
            table.insert(errors, ">> # " .. k)
          end
          for _, err in pairs(v) do
            if extra_infos["machine_readable"] then
              table.insert(errors, json.encode({error="allof.suberror", path=path, key=k, suberr=json.decode(err)}))
            else
              table.insert(errors, ">> " .. err)
            end
          end
        else
          if extra_infos["machine_readable"] then
            table.insert(errors, json.encode({error="allof.suberror", path=path, suberr=json.decode(v)}))
          else
            table.insert(errors, ">> " .. v)
          end
        end
      end
      return false
    end
  end

  -- look up correct subvalidator
  if json_validators[schema_type] then
    validator_found = true
    debug_print("Entering " .. schema_type .. " validation at " .. path)
    local retval = json_validators[schema_type](content, schema, path, errors, extra_infos)
    if retval then
      debug_print("Left " .. schema_type .. " validation at " .. path .. " (success?)")
    else
      debug_print("Left " .. schema_type .. " validation at " .. path .. " (fail?)")
    end
    return retval
  end

  if not validator_found then
    debug_print("Unknown schema type at " .. path)
    for k, v in pairs(schema) do
      debug_print(string.format("%s = %s", "schema[" .. k .. "]", v))
    end
    if schema_type == nil then
      debug_print("No schema type found at " .. path)
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="schema.notype", path=path}))
      else
        table.insert(errors, "No schema type found at " .. path)
      end
    else
      debug_print("Unknown schema type '" .. schema_type .. "' at " .. path)
      if extra_infos["machine_readable"] then
        table.insert(errors, json.encode({error="schema.unknowntype", path=path, details=schema_type}))
      else
        table.insert(errors, "Unknown schema type '" .. schema_type .. "' at " .. path)
      end
      return false
    end
  end

  -- fallthrough: at least one part above has matched and not found any issues
  return true
end

-- main entrypoint
function validate_json_main(content, schema, path, errors, extra_infos, spec)
  openapi_spec = spec
  return validate_json(content, schema, path, errors, extra_infos)
end

-- helper functions
function openapi_resolve_reference(ref)
    local refval = openapi_spec["components"][ref]
    if refval == nil then
         error('Referenced component ' .. tostring(ref) .. ' not found')
    end
    if refval['$ref'] ~= nil then
        return openapi_resolve_reference(refval['$ref'])
    else
        return refval
    end
end

function openapi_get_value(dict, key)
    if dict == nil then return nil end

    local value = dict[key]

    if value == nil and dict['$ref'] ~= nil then
        value = openapi_resolve_reference(dict['$ref'])[key]
        if value ~= nil then return value end
    end

    if value == nil and dict['parent'] ~= nil then
        if key == "type" then
            value = openapi_get_value(dict['parent'], key)
            if value == nil then
                -- TODO: find better workaround for undefined behaviour..
                value = "object"
            end
        end
    end

    return value
end

-- DEFINE LIB
lib = {}
lib["main"] = validate_json_main
return lib
