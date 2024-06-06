# Errors and Warnings

Common parameters:

- path: Contains the path to data inside of the original JSON request/response data
- value: Contains the contained value from the original JSON request/response data

## Generic errors

### `invalid-json`

JSON decoding failed

Additional parameters:

- details: Raw data

### `schema.notype`

Schema has no type defined for values at this path.

### `schema.unknowntype`

Schema has an unknown/unimplemented type value

Additional parameters:

- details: Given schema type

### `invalid-response-code`

Response contains a status code that is not listed inside of the response schema.

Additional parameters:

- details: Given status code

## Warnings

### `guessed-content-type`

Content type could not be found or does not match schema provided content types.

Since this is a common issue due to http2 stream compression and sometimes just
weird content types the dissector guessed a content type that has been used for
validation.

Additional parameters:

- details: Guessed content type

### `not-validated`

Content could not be validated (probably due to missing schema or wrong content
type).

### `multiple-matching-pathspecs`

Multiple path specs match the path for this request. Only the first match will
be used for validation.

### `no-response-code`

Response does not contain a status code.

Due to http2 stream compression this can sometimes happen for repeated
responses. Because it only seems to happen for empty responses which have
no data to be validated anyway this resulsts in just a warning instead of
a validation error.

### `path-not-found`

No path spec could be found for the given request path

## String

### `string.pattern`

Contained string doesn't match the required pattern (regular expression).

Additional parameters:

- details: Required pattern

### `string.wrongtype`

Given value should be a string, but seems to be something else.

## Boolean

### `bool.wrongtype`

Given value should be a boolean, but seems to be something else.

## Number

### `number.wrongtype`

Given value should be a number, but seems to be something else.

### `number.boundary.minimum`

Number is lower than the required minimum value.

Additional parameters:

- details: Schema defined minimum value

### `number.boundary.maximum`

Number is higher than the required maximum value.

Additional parameters:

- details: Schema defined maximum value

### `number.multipleof`

Number should be a multiple of given value, but is not.

Additional parameters:

- details: Schema defined multiplier

## Array

### `array.wrongtype`

Given value should be an array, but seems to be something else.

Additional parameters:

- details: Reason why value is not detected to be an array (non-table-structure/non-numeric-index/non-sequential-index)

### `array.minitems`

Array contains less items than it should.

Additional parameters:

- details: Defined minimum number of items

### `array.maxitems`

Array contains more items than it should.

Additional parameters:

- details: Defined maximum number of items

### `array.nonunique`

Array contains duplicate entries

## Objects

### `object.wrongtype`

Given value should be an object, but seems to be something else.

Additional parameters:

- details: Reason why value is not detected to be an object (non-table-structure)

### `object.missing_argument`

Object should contain specific key, but does not.

Additional parameters:

- details: Key of missing element

### `object.send_readonly`

Request object contains a key that should only be contained in response data.

Additional parameters:

- details: Key of readonly element

### `object.receive_writeonly`

Response object contains a key that should only be contained in request data.

Additional parameters:

- details: Key of writeonly element

### `object.forbidden_key`

Object contains a forbidden key.

Additional parameters:

- details: Forbidden key

### `object.unallowed_properties`

Object contains an unwanted key.

Additional parameters:

- details: Unwanted key

### `object.minproperties`

Object contains less properties than required.

Additional parameters:

- details: Number of required properties

### `object.maxproperties`

Object contains more properties than allowed.

Additional parameters:

- details: Number of allowed properties

### `object.disallowed_additional_property`

Object contains an additional unwanted key.

Additional parameters:

- details: Additional unwanted key


## Integer

Integer validation inherits error checking from number validation but also contains a few additional checks.

### `integer.wrongtype`

Given value should be an integer, but seems to be something else.

Additional parameters:

- details: Reason why value is not detected to be an integer (not-a-number/non-zero-decimal)

## Enum

### `enum.nomatch`

Value should match in enum, but does not.

## oneOf

### `oneof.discriminator_missing`

oneOf schema has defined a discriminator key, but it is missing inside the request/response data.

Additional parameters:

- subpath: Path to affected property

### `oneof.criterium_failed`

oneOf criterium failed (no valid sub-schemas found)

Additional parameters:

- details: dictionary containing
  - valid: number of valid sub-schemas
  - invalid: number of invalid sub-schemas

### `oneof.multiple_valid`

oneOf criterium failed (multiple valid sub-schemas)

Additional parameters:

- details: list of valid sub-schemas

### `oneof.suberror`

Contains errors detected during sub-schema validation

Additional parameters:

- key (not provided for all errors): additional schema path information
- suberr: error that occured inside of sub-schema validation (same format as parent)

## anyOf

### `anyof.criterium_failed`

anyOf criterium failed (no valid sub-schemas found)

Additional parameters:

- details: dictionary containing
  - valid: number of valid sub-schemas
  - invalid: number of invalid sub-schemas

### `anyof.suberror`

Contains errors detected during sub-schema validation

Additional parameters:

- key (not provided for all errors): additional schema path information
- suberr: error that occured inside of sub-schema validation (same format as parent)

## allOf

### `allof.criterium_failed`

allOf criterium failed (no all valid sub-schemas are valid)

Additional parameters:

- details: dictionary containing
  - valid: number of valid sub-schemas
  - invalid: number of invalid sub-schemas

### `allof.suberror`

Contains errors detected during sub-schema validation

Additional parameters:

- key (not provided for all errors): additional schema path information
- suberr: error that occured inside of sub-schema validation (same format as parent)
