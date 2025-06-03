from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from sigma.conversion.base import TextQueryBackend
from sigma.conditions import ConditionItem, ConditionAND, ConditionOR, ConditionNOT
from sigma.types import SigmaCompareExpression, SigmaRegularExpression, SigmaRegularExpressionFlag
import sigma
import re
import json
from typing import ClassVar, Dict, Tuple, Pattern, List, Any, Optional

class SecurityOnionBackend(TextQueryBackend):
    """OQL backend."""

    # Operator precedence: tuple of Condition{AND,OR,NOT} in order of precedence.
    # The backend generates grouping if required
    name : ClassVar[str] = "OQL backend"
    formats : Dict[str, str] = {
        "default": "Plain OQL queries",
        
    }
    requires_pipeline : bool = False

    precedence: ClassVar[Tuple[ConditionItem, ConditionItem, ConditionItem]] = (
        ConditionNOT,
        ConditionOR,
        ConditionAND,
    )
    parenthesize: bool = True
    group_expression : ClassVar[str] = "({expr})"   # Expression for precedence override grouping as format string with {expr} placeholder

    # Generated query tokens
    token_separator : str = " "
    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = ":"  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    # No quoting of field names



    ### Escaping
    field_escape : ClassVar[str] = "\\"               # Character to escape particular parts defined in field_escape_pattern.

    field_escape_pattern: ClassVar[Pattern] = re.compile("[\\s*]")   # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = '"'     # string quoting character (added as escaping character)
    str_quote_pattern: ClassVar[Pattern] = re.compile(r"^$")
    str_quote_pattern_negation: ClassVar[bool] = False
    escape_char: ClassVar[str] = "\\"    # Escaping character for special characrers inside string
    wildcard_multi: ClassVar[str] = "*"     # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "?"     # Character used as single-character wildcard
    add_escaped: ClassVar[str] = '+-=&|!()[]<>^"~*?:\\/ '    # Characters quoted in addition to wildcards and string quote

    bool_values: ClassVar[Dict[bool, str]] = {   # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # Regular expressions
    # Regular expression query as format string with placeholders {field} and {regex}
    re_expression: ClassVar[str] = "{field}:/{regex}/"
    # Character used for escaping in regular expressions
    re_escape_char: ClassVar[str] = "\\"
    re_escape: ClassVar[Tuple[str]] = ("/",)
    # Don't escape the escape char
    re_escape_escape_char: ClassVar[bool] = False


    # cidr expressions
    # CIDR expression query as format string with placeholders {field} = {value}
    cidr_expression: ClassVar[str] = "{field}:{network}\\/{prefixlen}"

    # Numeric comparison operators
    # Compare operation query as format string with placeholders {field}, {operator} and {value}
    compare_op_expression: ClassVar[str] = "{field}:{operator}{value}"
    # Mapping between CompareOperators elements and strings used as replacement
    # for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    # Expression for field has null value as format string with {field} placeholder for field name
    field_null_expression: ClassVar[str] = "NOT _exists_:{field}"

    # Check if a field exists in the log not the value
    field_exists_expression: ClassVar[str] = "_exists_:{field}"
    field_not_exists_expression: ClassVar[str] = "NOT _exists_:{field}"

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    # Convert OR as in-expression
    convert_or_as_in: ClassVar[bool] = True
    # Convert AND as in-expression
    convert_and_as_in: ClassVar[bool] = False
    # Values in list can contain wildcards. If set to False (default)
    # only plain values are converted into in-expressions.
    in_expressions_allow_wildcards: ClassVar[bool] = True
    # Expression for field in list of values as format string with
    # placeholders {field}, {op} and {list}
    field_in_list_expression: ClassVar[str] = "{field}{op}({list})"
    # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    or_in_operator: ClassVar[str] = ":"
    # List element separator
    list_separator: ClassVar[str] = " OR "

    # Value not bound to a field
    # Expression for string value not bound to a field as format string with placeholder {value}
    unbound_value_str_expression: ClassVar[str] = "*{value}*"
    # Expression for number value not bound to a field as format string with placeholder {value}
    unbound_value_num_expression: ClassVar[str] = "{value}"

    
    # Query finalization: appending and concatenating deferred query part
    deferred_start : ClassVar[str] = "\n| "               # String used as separator between main query and deferred parts
    deferred_separator : ClassVar[str] = "\n| "           # String used to join multiple deferred query parts
    deferred_only_query : ClassVar[str] = "*"            # String used as query if final query only contains deferred expression
    

    def finalize_query(self, rule: SigmaRule, query: str, index: int, state: ConversionState, output_format: str) -> str:
        """Finalize query by adding field grouping if specified in the rule and aggregation is not disabled"""
        fields = rule.fields if hasattr(rule, "fields") else []
        
        if fields:
            # Check if aggregation field exists and is not false
            should_aggregate = True
            if hasattr(rule, "custom_attributes") and isinstance(rule.custom_attributes, dict):
                should_aggregate = rule.custom_attributes.get("aggregation", True)
            
            if should_aggregate:
                groupby_fields = [f"{field}*" if field not in ['source.ip', 'source.port', 'destination.ip', 'destination.port'] else field for field in fields]
                query = f"{query} | groupby {' '.join(groupby_fields)}"
            else:
                groupby_fields = [field for field in fields]
                query = f"{query} | table @timestamp {' '.join(groupby_fields)}"

        return json.dumps({
            "query": query,
            "fields": fields
        })