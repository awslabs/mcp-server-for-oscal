# Standalone Dockerfile for manual container builds/testing.
# hatch run build-agentcore-container
FROM public.ecr.aws/docker/library/python:3.12-slim
ARG VERSION
ARG WHL_FILE=mcp_server_for_oscal-${VERSION}-py3-none-any.whl
WORKDIR /app

# COPY requirements.txt requirements.txt
RUN --mount=type=bind,source=build/${WHL_FILE},target=/tmp/${WHL_FILE} \
    pip install /tmp/${WHL_FILE}

# Create non-root user
RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

# AgentCore requires binding to all interfaces and stateless HTTP mode
ENV OSCAL_MCP_HOST=0.0.0.0
ENV OSCAL_MCP_STATELESS_HTTP=true
ENV OSCAL_MCP_TRANSPORT=streamable-http

EXPOSE 8000

CMD ["server"]
