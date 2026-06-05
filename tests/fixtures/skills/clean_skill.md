---
skill: file-organizer
version: "1.2.0"
author: dev-team
invocation criteria: When the user asks to organize or sort files in a directory
---

# SKILL.md - File Organizer

## Description

This skill organizes files in a specified directory by categorizing them into subdirectories based on file type (documents, images, videos, archives).

## Invocation Criteria

- User requests file organization
- User asks to sort or categorize files
- User mentions cleaning up a directory

## Capabilities

- Read directory contents
- Create subdirectories by file type
- Move files to appropriate subdirectories
- Generate an organization report

## Limitations

- Only operates on user-specified directories
- Does not delete any files
- Maximum of 1000 files per operation
- Requires explicit user confirmation before moving files

## Output

Returns a summary of:
- Files processed
- Directories created
- Files moved per category
