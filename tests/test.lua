package.path = package.path .. ";../src/?.lua;../generator/?.lua;../lib/*.lua"
package.cpath = package.cpath .. ";../lib/?.so"

local json_validator = require "json_validator"
local openapi_spec = require "openapi_spec"
local rex_pcre2 = require "rex_pcre2"

function find_path_specs(_method, _path, _search)
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
        -- print("returning method " .. method .. " foo")
        return search[method]
      else
        -- print("returning method foo")
        return {}
      end
    else
      local path_part = string.match(path, "[^/?]+")
      local results = {}

      -- print("path part: ".. path_part)
      for pattern, subtable in pairs(search) do
        if rex_pcre2.match(path_part, pattern) then
          for _, entry in pairs(find_path_specs(method, string.sub(path, string.len(path_part)+1), subtable)) do
            if type(entry) == "number" then
              print("Found path spec id:", entry)
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

function hexdecode(hex)
  return (hex:gsub("%x%x", function(digits) return string.char(tonumber(digits, 16)) end))
end

function mysplit (inputstr, sep)
  if sep == nil then
    sep = "%s"
  end
  local t={}
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
    table.insert(t, str)
  end
  return t
end

-- testjson = hexdecode("7b0a09226175746854797065223a092235475f414b41222c0a092261757468656e7469636174696f6e566563746f72223a097b0a090922617635474865416b61223a097b0a09090922617654797065223a092235475f48455f414b41222c0a0909092272616e64223a09224130313630434437363236433835324237334234384131423535364342353538222c0a090909227872657353746172223a09223437344636343330303643364242364136433235423545453442323942363945222c0a090909226175746e223a09224641384138383536423043333830303042393931423534424444393936384432222c0a090909226b61757366223a092242343546454544373333453838344141364442373043464633413941323033443944313843454344324635413946453437463638434533414433394541414533220a09097d2c0a090922617654797065223a092235475f48455f414b41220a097d2c0a092273757069223a0922696d73692d303031303131323334353637383931220a7d")
-- testschema = find_path_specs("POST", "/nudm-ueau/v1/suci-0-001-01-0-0-0-0142000000/security-information/generate-auth-data")[1]["responses"]["200"]["content"]["application/json"]["schema"]

testjson = arg[4]

path_spec = nil
if arg[6] ~= "" then
  local specparts = mysplit(arg[6], ";")

  for k, v in pairs(openapi_spec["path_specs"]) do
    if v["document"] == specparts[1] and v["operationId"] == specparts[2] then
      path_spec = v
      break
    end
  end

  for k, v in pairs(specparts) do
    if k ~= 1 and k ~= 2 then
      path_spec = path_spec[v]
    end
  end
else
  path_spec = find_path_specs(arg[1], arg[2])[1]
end

testschema = nil
if arg[5] == "response" then
  responses = path_spec["responses"]
  if responses[arg[3]] then
    foobar = responses[arg[3]]["content"]
  else
    foobar = responses["default"]["content"]
  end

  if foobar["application/json"] == nil then
    for k, v in pairs(foobar) do
      if rex_pcre2.match(k, "^application/.*json") then
        foobar["application/json"] = foobar[k]
      end
    end
  end

  testschema = foobar["application/json"]["schema"]
else
  testschema = path_spec["requestBody"]["content"]["application/json"]["schema"]
end

local extra_infos = {}
extra_infos["type"] = arg[5]
extra_infos["callback_map"] = {}
extra_infos["callback_spec"] = {}

errors = {}
if json_validator.validate_raw_json(testjson, testschema, "root", errors, extra_infos) then
  print("")
  print("seems to be valid")
else
  print("")
  print("seems to be invalid")
end
print("")
print("# Errors")
for _, v in pairs(errors) do
  print(v)
end

