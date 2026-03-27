---
inclusion: always
---
<!------------------------------------------------------------------------------------
   Add rules to this file or a short description that will apply across all your workspaces.
   
   Learn about inclusion modes: https://kiro.dev/docs/steering/#inclusion-modes
-------------------------------------------------------------------------------------> 
- Before you start implementing tasks, check your git branch. The main branch is named main. NEVER commit to the main branch without approval.

 - This project uses GitHub for version control, task and issue management, CI/CD, etc. The basic workflow looks like: GitHub issue -> new feature-branch -> checkout branch locally -> implement and commit -> push to GitHub -> create pull request -> merge pull request -> delete feature branch.

- In spec mode, after requirements are done and approved, use the GitHub cli `gh` to search for an existing, related issue. If you don't find one, draft a new one for user to review and ask for approval before you create it. Then create the feature branch from the issue using GitHub cli. Your first commit to the feature-branch should be the spec files. 

- A feature-branch should be used only for a single feature. If it seems appropriate to reuse a feature-branch, ask user for approval.

- Consider committing changes to the feature-branch at each checkpoint or when each group of tasks is complete. Do not commit while debugging. In commit messages, indicate whether code has been tested successfully or not. Always include the GitHub issue number in your commit message, for example: #00. 

- Don't forget to commit the updated tasks.md file when appropriate.

- Run the full test suite `hatch run tests` before commit.

- Only add, stage, or commit files that you created or modified for this feature. Do not add, stage, or commit unrelated files.

- This git-strategy is in addition to the rules in amazon-builder-git global steering. In case there is a conflict between the two, stop immediately and ask the user what to do next.

NEVER commit to the main branch without approval.
NEVER PUSH CODE TO A REMOTE/ORIGIN SERVER WITHOUT EXPLICIT APPROVAL FROM THE USER.