import boto3
from strands import Agent
from strands.models import BedrockModel

# Import configuration
from mcp_server_for_oscal.config import config


def create_oscal_agent(s: boto3.Session) -> Agent:
    """Create and configure the OSCAL agent."""

    system_prompt = """You are an OSCAL (Open Security Controls Assessment Language) expert assistant.

You help users understand OSCAL concepts, models, and implementation approaches. You have access to tools that can:
1. Fetch official NIST OSCAL documentation
2. List available OSCAL model types
3. Provide detailed information about specific OSCAL models

When answering questions:
- Always use the official NIST documentation when available
- Provide practical, actionable guidance
- Explain concepts clearly for both beginners and experts
- Reference official sources and examples
- If you need specific documentation, use the fetch_oscal_documentation tool

You are knowledgeable about:
- OSCAL architecture and layers (Control, Implementation, Assessment)
- All OSCAL model types and their relationships
- OSCAL implementation best practices
- Integration with compliance frameworks like NIST SP 800-53, FedRAMP, etc.
"""

    # Use a valid Bedrock model identifier
    agent = Agent(
        model=BedrockModel(model_id=config.bedrock_model_id, boto_session=s),
        load_tools_from_directory=True,
        system_prompt=system_prompt,
    )

    return agent
