"""
Tests for the query_documentation tool.
"""

from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from mcp_server_for_oscal.tools.query_documentation import query_oscal_documentation


class TestQueryDocumentation:
    """Test cases for the query_oscal_documentation tool."""

    @pytest.fixture
    def mock_context(self):
        """Create a mock MCP context."""
        context = Mock()
        context.error = Mock()
        return context

    @pytest.fixture
    def mock_bedrock_response(self):
        """Create a mock Bedrock retrieve response."""
        return {
            'retrievalResults': [
                {
                    'content': {
                        'text': 'OSCAL is a framework for security controls.'
                    },
                    'location': {
                        's3Location': {
                            'uri': 's3://bucket/document.pdf'
                        }
                    },
                    'score': 0.95,
                    'metadata': {
                        'source': 'NIST OSCAL Documentation'
                    }
                }
            ],
            'nextToken': 'next-token-123'
        }

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_success_with_profile(self, mock_config, mock_session_class, mock_context, mock_bedrock_response):
        """Test successful documentation query with AWS profile."""
        # Setup mocks
        mock_config.aws_profile = "test-profile"
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        result = query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify results
        assert result == mock_bedrock_response
        mock_session_class.assert_called_once_with(profile_name="test-profile")
        mock_session.client.assert_called_once_with("bedrock-agent-runtime")
        mock_client.retrieve.assert_called_once_with(
            knowledgeBaseId="test-kb-id",
            retrievalQuery={"text": "What is OSCAL?"}
        )

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_success_without_profile(self, mock_config, mock_session_class, mock_context, mock_bedrock_response):
        """Test successful documentation query without AWS profile."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        result = query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify results
        assert result == mock_bedrock_response
        mock_session_class.assert_called_once_with()
        mock_session.client.assert_called_once_with("bedrock-agent-runtime")
        mock_client.retrieve.assert_called_once_with(
            knowledgeBaseId="test-kb-id",
            retrievalQuery={"text": "What is OSCAL?"}
        )

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_client_error(self, mock_config, mock_session_class, mock_context):
        """Test handling of AWS client errors."""
        # Setup mocks
        mock_config.aws_profile = "test-profile"
        mock_config.knowledge_base_id = "invalid-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        error_response = {
            'Error': {
                'Code': 'ResourceNotFoundException',
                'Message': 'Knowledge base not found'
            }
        }
        mock_client.retrieve.side_effect = ClientError(error_response, 'Retrieve')
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test and verify exception
        with pytest.raises(Exception):
            query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify error handling
        mock_context.error.assert_called_once()
        error_call_args = mock_context.error.call_args[0][0]
        assert "Error running query" in error_call_args
        assert "What is OSCAL?" in error_call_args

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_no_credentials_error(self, mock_config, mock_session_class, mock_context):
        """Test handling of AWS credentials errors."""
        # Setup mocks
        mock_config.aws_profile = "nonexistent-profile"
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session_class.side_effect = NoCredentialsError()

        # Execute test and verify exception
        with pytest.raises(Exception):
            query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify error handling
        mock_context.error.assert_called_once()

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_empty_query(self, mock_config, mock_session_class, mock_context, mock_bedrock_response):
        """Test query with empty string."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        result = query_oscal_documentation("", mock_context)

        # Verify results
        assert result == mock_bedrock_response
        mock_client.retrieve.assert_called_once_with(
            knowledgeBaseId="test-kb-id",
            retrievalQuery={"text": ""}
        )

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_complex_query(self, mock_config, mock_session_class, mock_context, mock_bedrock_response):
        """Test query with complex multi-line text."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        complex_query = """
        What are the key components of an OSCAL System Security Plan?
        Please include information about:
        - Control implementations
        - System characteristics
        - Authorization boundary
        """

        # Execute test
        result = query_oscal_documentation(complex_query, mock_context)

        # Verify results
        assert result == mock_bedrock_response
        mock_client.retrieve.assert_called_once_with(
            knowledgeBaseId="test-kb-id",
            retrievalQuery={"text": complex_query}
        )

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    @patch('mcp_server_for_oscal.tools.query_documentation.logger')
    def test_query_documentation_logging(self, mock_logger, mock_config, mock_session_class, mock_context, mock_bedrock_response):
        """Test that appropriate logging occurs."""
        # Setup mocks
        mock_config.aws_profile = "test-profile"
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "DEBUG"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify logging calls
        mock_logger.debug.assert_called()
        debug_calls = [call[0][0] for call in mock_logger.debug.call_args_list]
        assert any("Using AWS profile: test-profile" in call for call in debug_calls)

    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_empty_response(self, mock_config, mock_session_class, mock_context):
        """Test handling of empty response from Bedrock."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "INFO"

        empty_response = {
            'retrievalResults': [],
            'nextToken': None
        }

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = empty_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        result = query_oscal_documentation("Nonexistent topic", mock_context)

        # Verify results
        assert result == empty_response
        assert result['retrievalResults'] == []

    @patch('mcp_server_for_oscal.tools.query_documentation.json.dumps')
    @patch('mcp_server_for_oscal.tools.query_documentation.Session')
    @patch('mcp_server_for_oscal.tools.query_documentation.config')
    def test_query_documentation_json_logging(self, mock_config, mock_session_class, mock_json_dumps, mock_context, mock_bedrock_response):
        """Test that response is logged as JSON."""
        # Setup mocks
        mock_config.aws_profile = None
        mock_config.knowledge_base_id = "test-kb-id"
        mock_config.log_level = "DEBUG"

        mock_session = Mock()
        mock_client = Mock()
        mock_client.retrieve.return_value = mock_bedrock_response
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        # Execute test
        query_oscal_documentation("What is OSCAL?", mock_context)

        # Verify JSON logging
        mock_json_dumps.assert_called_once_with(mock_bedrock_response, indent=1)
