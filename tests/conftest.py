"""
Pytest configuration and shared fixtures for OSCAL MCP Server tests.
"""

import os
from unittest.mock import Mock

import pytest


@pytest.fixture
def mock_context():
    """Create a mock MCP context for testing tools."""
    context = Mock()
    context.error = Mock()
    context.session = Mock()
    context.session.client_params = {}
    return context


@pytest.fixture
def mock_config():
    """Create a mock configuration object with default values."""
    config = Mock()
    config.bedrock_model_id = "us.anthropic.claude-sonnet-4-20250514-v1:0"
    config.knowledge_base_id = ""
    config.aws_profile = None
    config.aws_region = None
    config.log_level = "INFO"
    config.server_name = "OSCAL MCP Server"
    config.update_from_args = Mock()
    return config


@pytest.fixture
def sample_bedrock_response():
    """Create a sample Bedrock knowledge base response."""
    return {
        'retrievalResults': [
            {
                'content': {
                    'text': 'OSCAL (Open Security Controls Assessment Language) is a set of formats that provide machine-readable representations of control catalogs, control baselines, system security plans, and assessment plans and results.'
                },
                'location': {
                    's3Location': {
                        'uri': 's3://oscal-kb-bucket/nist-oscal-docs/oscal-overview.pdf'
                    }
                },
                'score': 0.95,
                'metadata': {
                    'source': 'NIST OSCAL Documentation',
                    'title': 'OSCAL Overview',
                    'x-amz-bedrock-kb-source-uri': 's3://oscal-kb-bucket/nist-oscal-docs/oscal-overview.pdf'
                }
            },
            {
                'content': {
                    'text': 'OSCAL enables organizations to automate control implementation and assessment activities.'
                },
                'location': {
                    's3Location': {
                        'uri': 's3://oscal-kb-bucket/nist-oscal-docs/oscal-implementation.pdf'
                    }
                },
                'score': 0.87,
                'metadata': {
                    'source': 'NIST OSCAL Implementation Guide',
                    'title': 'OSCAL Implementation',
                    'x-amz-bedrock-kb-source-uri': 's3://oscal-kb-bucket/nist-oscal-docs/oscal-implementation.pdf'
                }
            }
        ],
        'nextToken': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    }


@pytest.fixture
def sample_json_schema():
    """Create a sample OSCAL JSON schema."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "$id": "https://raw.githubusercontent.com/usnistgov/OSCAL/v1.1.2/json/schema/oscal_catalog_schema.json",
        "title": "OSCAL Control Catalog Model: JSON Schema",
        "description": "OSCAL Control Catalog Model: JSON Schema",
        "$comment": "OSCAL catalog model: JSON Schema",
        "type": "object",
        "definitions": {
            "catalog": {
                "title": "Catalog",
                "description": "A structured, organized collection of control information.",
                "type": "object",
                "properties": {
                    "uuid": {
                        "title": "Catalog Universally Unique Identifier",
                        "description": "Provides a globally unique means to identify a given catalog instance.",
                        "type": "string",
                        "pattern": "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}$"
                    },
                    "metadata": {
                        "$ref": "#/definitions/metadata"
                    },
                    "params": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "$ref": "#/definitions/parameter"
                        }
                    },
                    "controls": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "$ref": "#/definitions/control"
                        }
                    },
                    "groups": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "$ref": "#/definitions/group"
                        }
                    },
                    "back-matter": {
                        "$ref": "#/definitions/back-matter"
                    }
                },
                "required": [
                    "uuid",
                    "metadata"
                ],
                "additionalProperties": False
            },
            "metadata": {
                "title": "Publication metadata",
                "description": "Provides information about the containing document, and defines a set of document-level metadata.",
                "type": "object",
                "properties": {
                    "title": {
                        "title": "Document Title",
                        "description": "A name given to the document, which may be used by a tool for display and navigation.",
                        "type": "string"
                    },
                    "published": {
                        "title": "Publication Timestamp",
                        "description": "The date and time the document was published.",
                        "type": "string",
                        "format": "date-time",
                        "pattern": "^((2000|2400|2800|(19|2[0-9](0[48]|[2468][048]|[13579][26])))-02-29)|(((19|2[0-9])[0-9]{2})-02-(0[1-9]|1[0-9]|2[0-8]))|(((19|2[0-9])[0-9]{2})-(0[13578]|10|12)-(0[1-9]|[12][0-9]|3[01]))|(((19|2[0-9])[0-9]{2})-(0[469]|11)-(0[1-9]|[12][0-9]|30))T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"
                    },
                    "last-modified": {
                        "title": "Last Modified Timestamp",
                        "description": "The date and time the document was last modified.",
                        "type": "string",
                        "format": "date-time",
                        "pattern": "^((2000|2400|2800|(19|2[0-9](0[48]|[2468][048]|[13579][26])))-02-29)|(((19|2[0-9])[0-9]{2})-02-(0[1-9]|1[0-9]|2[0-8]))|(((19|2[0-9])[0-9]{2})-(0[13578]|10|12)-(0[1-9]|[12][0-9]|3[01]))|(((19|2[0-9])[0-9]{2})-(0[469]|11)-(0[1-9]|[12][0-9]|30))T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$"
                    },
                    "version": {
                        "title": "Document Version",
                        "description": "A string used to distinguish the current version of the document from other previous (and future) versions.",
                        "type": "string"
                    },
                    "oscal-version": {
                        "title": "OSCAL version",
                        "description": "The OSCAL model version the document was authored against.",
                        "type": "string"
                    }
                },
                "required": [
                    "title",
                    "last-modified",
                    "version",
                    "oscal-version"
                ],
                "additionalProperties": False
            }
        },
        "properties": {
            "catalog": {
                "$ref": "#/definitions/catalog"
            }
        },
        "required": [
            "catalog"
        ],
        "additionalProperties": False
    }


@pytest.fixture
def sample_xsd_schema():
    """Create a sample OSCAL XSD schema content."""
    return '''<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
           xmlns:oscal="http://csrc.nist.gov/ns/oscal/1.0"
           targetNamespace="http://csrc.nist.gov/ns/oscal/1.0"
           elementFormDefault="qualified"
           version="1.1.2">

  <xs:annotation>
    <xs:documentation>
      <h1>OSCAL Control Catalog Model: XML Schema</h1>
      <p>The OSCAL Control Catalog format can be used to describe a collection of security controls and related control enhancements, along with contextualizing documentation and metadata.</p>
    </xs:documentation>
  </xs:annotation>

  <xs:element name="catalog" type="oscal:CatalogType"/>

  <xs:complexType name="CatalogType">
    <xs:annotation>
      <xs:documentation>
        <b>Catalog</b>: A structured, organized collection of control information.
      </xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="metadata" type="oscal:MetadataType"/>
      <xs:element name="param" type="oscal:ParameterType" minOccurs="0" maxOccurs="unbounded"/>
      <xs:element name="control" type="oscal:ControlType" minOccurs="0" maxOccurs="unbounded"/>
      <xs:element name="group" type="oscal:GroupType" minOccurs="0" maxOccurs="unbounded"/>
      <xs:element name="back-matter" type="oscal:BackMatterType" minOccurs="0"/>
    </xs:sequence>
    <xs:attribute name="uuid" type="oscal:UUIDDatatype" use="required"/>
  </xs:complexType>

  <xs:complexType name="MetadataType">
    <xs:annotation>
      <xs:documentation>
        <b>Publication metadata</b>: Provides information about the containing document, and defines a set of document-level metadata.
      </xs:documentation>
    </xs:annotation>
    <xs:sequence>
      <xs:element name="title" type="xs:string"/>
      <xs:element name="published" type="xs:dateTime" minOccurs="0"/>
      <xs:element name="last-modified" type="xs:dateTime"/>
      <xs:element name="version" type="xs:string"/>
      <xs:element name="oscal-version" type="xs:string"/>
    </xs:sequence>
  </xs:complexType>

  <xs:simpleType name="UUIDDatatype">
    <xs:restriction base="xs:string">
      <xs:pattern value="[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[45][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}"/>
    </xs:restriction>
  </xs:simpleType>

</xs:schema>'''


@pytest.fixture
def mock_aws_session():
    """Create a mock AWS session with Bedrock client."""
    session = Mock()
    client = Mock()
    session.client.return_value = client
    return session, client


@pytest.fixture
def clean_environment():
    """Provide a clean environment for testing configuration."""
    # Store original environment
    original_env = dict(os.environ)

    # Clear relevant environment variables
    env_vars_to_clear = [
        'BEDROCK_MODEL_ID',
        'OSCAL_KB_ID',
        'AWS_PROFILE',
        'AWS_REGION',
        'LOG_LEVEL',
        'OSCAL_MCP_SERVER_NAME'
    ]

    for var in env_vars_to_clear:
        if var in os.environ:
            del os.environ[var]

    yield

    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def mock_schema_file():
    """Create a mock schema file handle."""
    file_mock = Mock()
    file_mock.read.return_value = '{"test": "schema"}'
    return file_mock


@pytest.fixture
def all_oscal_model_types():
    """Provide all OSCAL model types for testing."""
    from mcp_server_for_oscal.tools.utils import OSCALModelType
    return list(OSCALModelType)


@pytest.fixture
def sample_model_list():
    """Create a sample model list response."""
    return {
        "catalog": {
            "description": "A structured set of controls and control enhancements",
            "layer": "Control",
            "status": "GA"
        },
        "profile": {
            "description": "A baseline or overlay that selects and customizes controls from catalogs",
            "layer": "Control",
            "status": "Prototype"
        },
        "component-definition": {
            "description": "Describes how components implement controls",
            "layer": "Implementation",
            "status": "GA"
        },
        "system-security-plan": {
            "description": "Documents how a system implements required controls",
            "layer": "Implementation",
            "status": "GA"
        },
        "assessment-plan": {
            "description": "Defines how controls will be assessed",
            "layer": "Assessment",
            "status": "GA"
        },
        "assessment-results": {
            "description": "Documents the results of control assessments",
            "layer": "Assessment",
            "status": "GA"
        },
        "plan-of-action-and-milestones": {
            "description": "Documents remediation plans for identified issues",
            "layer": "Assessment",
            "status": "GA"
        },
        "mapping-collection": {
            "description": "Describes how a collection of security controls relates to another collection of controls",
            "layer": "Control",
            "status": "GA"
        }
    }


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location."""
    import inspect

    for item in items:
        # Mark integration tests
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        else:
            item.add_marker(pytest.mark.unit)

        # Mark async tests
        if hasattr(item.function, '__code__') and inspect.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)

