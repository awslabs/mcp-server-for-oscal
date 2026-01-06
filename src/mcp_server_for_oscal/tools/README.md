# Provided OSCAL tools

## 1. List OSCAL Models  
- **Tool**: `list_oscal_models`
- Retrieve all available OSCAL model types with descriptions, layers, and status
- Understand the different OSCAL models and their purposes

## 2. Get OSCAL Schemas
- **Tool**: `get_oscal_schema`  
- Retrieve JSON or XSD schemas for current GA release of individual OSCAL models. Because OSCAL schemas are self-documenting, this is equivalent to querying model documentation.
- Used to answer questions about the structure, properties, requirements of each OSCAL model

## 3. List OSCAL Community Resources
- **Tool**: `list_oscal_resources`
- Access a curated collection of OSCAL community resources from [Awesome OSCAL](https://github.com/oscal-club/awesome-oscal)
- Get information about available OSCAL tools, content, articles, presentations, and educational materials
- Includes resources from government agencies, security organizations, and the broader OSCAL community

## 4. Query OSCAL Documentation
- **Tool**: `query_oscal_documentation`
- Query authoritative OSCAL documentation using Amazon Bedrock Knowledge Base (KB). Note that this feature requires you to setup and maintain a Bedrock KB in your AWS account. In future, we hope to provide this as a service.
- Get answers to questions about OSCAL concepts, best practices, and implementation guidance.