#!/usr/bin/env python3

import yaml
import glob
import os
import pickle
import json
import urllib.parse
import pathlib
import sys

PRECOMPILE_REGEXES = True

PATTERNS = {
    "string": "[^/]+",
    "integer": "-?[0-9]+",
}

STRING_ESCAPE = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "",
}

def lua_string_escape(text):
    out = ""
    for c in text:
        if c in STRING_ESCAPE:
            out += STRING_ESCAPE[c]
        else:
            out += c
    return out

# Extend all references with their corresponding document name so they can still be identified when merged into a single file
def expand_references(part, expand):
    if isinstance(part, dict):
        for key, subpart in part.items():
            if key == "discriminator" and "mapping" in subpart:
                for key, value in subpart["mapping"].items():
                    if value.startswith('#'):
                        subpart["mapping"][key] = expand + value
            elif key == '$ref':
                if part[key].startswith('#'):
                    part[key] = expand + subpart
            else:
                expand_references(subpart, expand)
    elif isinstance(part, list):
        for i, subpart in enumerate(part):
            expand_references(subpart, expand)

# Convert given object into native Lua data structure
def obj_to_lua(path, obj, parent=None):
    out = ""
    if isinstance(obj, dict):
        out += f'{path} = {{}}\n'
        for key, subobj in obj.items():
            out += obj_to_lua(f'{path}["{lua_string_escape(key)}"]', subobj, parent=obj)
    elif isinstance(obj, list):
        out += f'{path} = {{}}\n'
        for key, subobj in enumerate(obj):
            out += obj_to_lua(f'{path}[{key}]', subobj, parent=obj)
    elif isinstance(obj, str):
        if path.endswith("[pattern]"):
            out += f'{path} = rex_pcre2.new("{lua_string_escape(obj)}")\n'
        else:
            out += f'{path} = "{lua_string_escape(obj)}"\n'
    elif isinstance(obj, bool):
        out += f'{path} = {"true" if obj else "false"}\n'
    elif isinstance(obj, int) or isinstance(obj, float):
        out += f'{path} = {obj}\n'
    elif obj is None:
        out += f'{path} = nil\n'
    else:
        print("what is this?", obj)

    return out

# Generate regular expression for path matching, including basic support for url parameters
def generate_path_part_pattern(path, parameters):
    path_pattern = "^" + path.replace("/", "\\/") + "$"
    for param in parameters.values():
        if "in" in param and param["in"] == "path":
            schema = param["schema"]
            while '$ref' in schema:
                schema = components[schema['$ref']]

            if "pattern" in schema:
                pattern = schema["pattern"].lstrip("^").rstrip("$")
            elif 'anyOf' in schema:
                subpatterns = []
                for part in schema["anyOf"]:
                    while '$ref' in part:
                        part = components[part['$ref']]
                    if 'enum' in part:
                        subpattern = "(" + ("|".join(part["enum"])) + ")"
                    else:
                        subpattern = PATTERNS[part["type"]]
                    subpatterns.append(subpattern)
                pattern = "(" + ("|".join(subpatterns)) + ")"
            elif 'type' in schema and schema['type'] == 'object':
                subpatterns = []
                for name, subschema in schema["properties"].items():
                    while '$ref' in subschema:
                        subschema = components[subschema['$ref']]
                    if 'pattern' in subschema:
                        subpattern = "(" + subschema["pattern"].lstrip("^").rstrip("$") + ")"
                    elif 'type' in subschema:
                        subpattern = "(" + PATTERNS[subschema["type"]] + ")"
                    else:
                        print(subschema)
                        raise Exception("fnord")
                    subpatterns.append(subpattern)
                pattern = "(" + ("|".join(subpatterns)) + ")"
            elif 'type' in schema and schema["type"] == "array":
                # TODO: implement
                pattern = "[^/]+"
            elif 'type' in schema:
                pattern = PATTERNS[schema["type"]]
            else:
                raise Exception("unknown schema: " + repr(schema))

            path_pattern = path_pattern.replace("{%s}" % param['name'], "(%s)" % pattern)
    return path_pattern

# Generate path data structure containing generated regular expressions
def generate_path_pattern(specname, root, path, parameters):
    path = root + path

    if not path.startswith("/"):
        raise Exception("weird path, doesn't start at root: %s" % path)

    luapath = f'lib["specs"]["{specname}"]["path_patterns"]'
    tmplua = ''
    for path_part in path.split("/")[1:]:
        path_part_pattern = generate_path_part_pattern(path_part, parameters)
        luapath += f'["{lua_string_escape(path_part_pattern)}"]'

        tmplua += f'if {luapath} == nil then\n'
        tmplua += f'  {luapath} = {{}}\n'
        tmplua += f'end\n'

    return (luapath, tmplua)

lua = 'json = require "json"\n'
lua += 'if rex_pcre2 == nil then\n'
lua += '  rex_pcre2 = require "rex_pcre2"\n'
lua += 'end\n'
lua += 'lib = {}\n'
lua += 'lib["specs"] = {}\n'
lua += 'lib["spec_names"] = {}\n'

lua += 'function compile_patterns(source)\n'
lua += '  local compiled = {}\n'
lua += '  for key, value in pairs(source) do\n'
lua += '    if value[1] == nil or type(value[1]) == "table" then\n'
lua += '      compiled[rex_pcre2.new(key)] = compile_patterns(value)\n'
lua += '    else\n'
lua += '      compiled[key] = value\n'
lua += '    end\n'
lua += '  end\n'
lua += '  return compiled\n'
lua += 'end\n'



for specdir in sorted(pathlib.Path(sys.argv[1]).glob("*")):
    if not specdir.is_dir():
        print(f"Skipping {specdir} (not a directory)")
        continue

    specname = specdir.name
    lua += f'table.insert(lib["spec_names"], "{specname}")\n'
    lua += f'lib["specs"]["{specname}"] = {{}}\n'
    lua += f'lib["specs"]["{specname}"]["documents"] = {{}}\n'
    lua += f'lib["specs"]["{specname}"]["components"] = {{}}\n'
    lua += f'lib["specs"]["{specname}"]["path_specs"] = {{}}\n'
    lua += f'lib["specs"]["{specname}"]["path_patterns"] = {{}}\n'

    # Load specification yaml files
    raw_specs = {}
    for path in sorted(pathlib.Path(specdir).glob("*.yaml")):
        print(f"Loading {path}")
        raw_yaml = open(path, "r", encoding="utf-8").read().replace("\t", "  ") # workaround for https://github.com/yaml/pyyaml/issues/594
        raw_specs[os.path.basename(path)] = yaml.safe_load(raw_yaml)

    components = {}
    paths = {}

    # OpenAPI specifications contain references to components and paths.
    # This codes prepares a corresponding lookup dictionary so that references
    # can be resolved.
    for document, spec in sorted(raw_specs.items()):
        print(f"Processing {document} components and metadata...")
        # Components
        if 'components' in spec:
            for section, items in spec["components"].items():
                for key, component in items.items():
                    path = document + "#/components/" + section + "/" + key
                    expand_references(component, document)
                    components[path] = component

        # Replace absolute Component paths in current document with relative paths
        if 'paths' in spec:
            for path_urlpart, pathspec in spec["paths"].items():
                pathname = f'{document}#/paths/{urllib.parse.quote(path_urlpart).replace("/", "~1")}'
                expand_references(pathspec, document)
                paths[pathname] = pathspec

        # Metadata
        lua += f'lib["specs"]["{specname}"]["documents"]["{lua_string_escape(document)}"] = {{}}\n'
        if "info" in spec:
            lua += obj_to_lua(f'lib["specs"]["{specname}"]["documents"]["{lua_string_escape(document)}"]["info"]', spec["info"])
        else:
            lua += f'lib["specs"]["{specname}"]["documents"]["{lua_string_escape(document)}"]["info"] = {{}}\n'
        if "externalDocs" in spec:
            lua += obj_to_lua(f'lib["specs"]["{specname}"]["documents"]["{lua_string_escape(document)}"]["externaldocs"]', spec["externalDocs"])
        else:
            lua += f'lib["specs"]["{specname}"]["documents"]["{lua_string_escape(document)}"]["externaldocs"] = {{}}\n'

    # Write all found components into the generated Lua data structure
    for component_path, component in sorted(components.items()):
        lua += obj_to_lua(f'lib["specs"]["{specname}"]["components"]["{component_path}"]', component)

    # This function combines all of the previously loaded and generated data to walk
    # through all paths of all documents, using previously defined functions to generate
    # path matching dictionaries and convert their corresponding schema into a Lua
    # data structure.
    path_spec_index = 1 # index to path_specs array (remember: lua starts counting at 1)
    for document, raw_spec in sorted(raw_specs.items()):
        print(f"Processing {document} paths...")
        servers = raw_spec["servers"] if "servers" in raw_spec else [{"url": "{apiRoot}"}]
        for server in servers:
            if 'paths' not in raw_spec: continue
            for path_urlpart, pathspec in raw_spec["paths"].items():
                while '$ref' in pathspec:
                    pathspec = paths[pathspec['$ref']]

                pathspec_parameters = {}
                if "parameters" in pathspec:
                    for param in pathspec["parameters"]:
                        pathspec_parameters[param["name"]] = param

                for method in ["get", "put", "post", "delete", "options", "head", "patch", "trace"]:
                    if method not in pathspec: continue
                    spec = pathspec[method]

                    parameters = pathspec_parameters.copy()
                    if "parameters" in spec:
                        for param in spec["parameters"]:
                            while '$ref' in param:
                                param = components[param['$ref']]
                            parameters[param["name"]] = param

                    try:
                        luapath, tmplua = generate_path_pattern(specname, server["url"].replace("{apiRoot}", "").replace("{root}", ""), path_urlpart, parameters)
                        lua += tmplua

                        lua += f'if {luapath}["{method}"] == nil then\n'
                        lua += f'    {luapath}["{method}"] = {{}}\n'
                        lua += f'end\n'
                        lua += f'table.insert({luapath}["{method}"], {path_spec_index})\n'

                        pathspec[method]["document"] = document
                        lua += obj_to_lua(f'lib["specs"]["{specname}"]["path_specs"][{path_spec_index}]', pathspec[method])

                        path_spec_index += 1
                    except:
                        print("ERR: Can't generate path pattern for %s%s (unspecified url parameter?)" % (server["url"].replace("{apiRoot}", "").replace("{root}", ""), path_urlpart))

    # rex_pcre2 (the Lua regex library that is also provided by Wireshark) allows
    # to compile regular expressions when they are being created so that they don't
    # need to be re-parsed every time they are being matched. This code compiles
    # all regular expressions inside of the path matching dictionary when the script
    # gets loaded.
    if PRECOMPILE_REGEXES:
        lua += f'lib["specs"]["{specname}"]["path_patterns"] = compile_patterns(lib["specs"]["{specname}"]["path_patterns"])\n'

lua += 'return lib\n'

open("openapi_spec.lua", "w", encoding="utf-8", newline="\n").write(lua)
