import pytest
from sigma.collection import SigmaCollection
from sigma.backends.SecurityOnion import SecurityOnionBackend

@pytest.fixture
def SecurityOnion_backend():
    return SecurityOnionBackend()

# TODO: implement tests for some basic queries and their expected results.
def test_SecurityOnion_and_expression(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['{"query": "fieldA:valueA AND fieldB:valueB", "fields": []}']

def test_SecurityOnion_or_expression(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['{"query": "fieldA:valueA OR fieldB:valueB", "fields": []}']

def test_SecurityOnion_and_or_expression(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['{"query": "(fieldA:(valueA1 OR valueA2)) AND (fieldB:(valueB1 OR valueB2))", "fields": []}']

def test_SecurityOnion_or_and_expression(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['{"query": "(fieldA:valueA1 AND fieldB:valueB1) OR (fieldA:valueA2 AND fieldB:valueB2)", "fields": []}']

def test_SecurityOnion_in_expression(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['{"query": "fieldA:(valueA OR valueB OR valueC*)", "fields": []}']

def test_SecurityOnion_regex_query(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['{"query": "fieldA:/foo.*bar/ AND fieldB:foo", "fields": []}']

def test_SecurityOnion_cidr_query(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['{"query": "field:192.168.0.0\\\\/16", "fields": []}']

def test_SecurityOnion_field_name_with_whitespace(SecurityOnion_backend : SecurityOnionBackend):
    assert SecurityOnion_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field name: value
                condition: sel
        """)
    ) == ['{"query": "field\\\\ name:value", "fields": []}']

# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
# implemented with custom code, deferred expressions etc.


