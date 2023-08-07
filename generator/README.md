# Specifications file generator

The specifications file generator prepares the OpenAPI specifications for use
with the dissector/validator by converting input in form of yaml files into
a Lua data structure that can easily be loaded.

Using the generator instead of parsing the specifications directly in Lua
results both in better loading speeds and that it's way easier to write some
of the code as a powerful language like Python can be used instead of having
to deal with the limitations of Lua.

The generated structure contains:

- All components defined in the input documents
- An array containing all path specifications from the input documents
- A nested dictionary of regular expressions for quickly matching paths to their corresponding specifications
