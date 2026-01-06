---
inclusion: always
---
<!------------------------------------------------------------------------------------
   Add rules to this file or a short description and have Kiro refine them for you.
   
   Learn about inclusion modes: https://kiro.dev/docs/steering/#inclusion-modes
-------------------------------------------------------------------------------------> 
A number of scripts and commands exist in `pyproject.toml` under the `*.scripts` sections. Most include descriptive names or comments. Running a script for a specific environment is simply  running `hatch run <env_name>:<script>`. You can omit the `<env_name>` for those under the `default` environment. 

To run any sort of external script within this project, use the command: `hatch run <path/to/script>`.

To run the project's full test suite and generate coverage metrics: `hatch run tests`.