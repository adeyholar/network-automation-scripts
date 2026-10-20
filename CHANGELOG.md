# Changelog

## palo_config_change.py

Newest first.

- 1.5.21 - Runs on Linux/macOS too (msvcrt optional, Enter fallback in countdown); XPath-safe object names; defusedxml parsing; history moved to CHANGELOG.md

- 1.5.20 - Safety fixes: TLS verification on by default (--insecure / NET_SCRIPTS_* env), --dry-run, backups never commit, commits are partial (own admin only) after typed confirmation, deleting an object removes it from rules instead of deleting rules, Ctrl+C during the exit countdown returns to the menu, keygen uses POST
- 1.5.19 - Fixed SyntaxError in main() function by completing the try-except block and ensuring proper function call syntax
- 1.5.18 - Added functionality to pull the 'default' virtual router configuration via API and output it to a CSV file for detailed analysis
- 1.5.17 - Updated script filename versioning to reset to v1 each day and increment within the day, appending the current date in MMDDYYYY format, as per the specified requirements
- 1.5.16 - Added a dedicated menu option to export only routing configurations (static and dynamic) to CSV files, providing more flexibility in output selection
- 1.5.15 - Added functionality to pull dynamic and static routing configurations via API and output them to separate CSV files for comprehensive network analysis
- 1.5.14 - Added functionality to pull all firewall policies via API and output them to a CSV file for easy analysis
- 1.5.13 - Updated restore_running_config to ensure the imported running configuration is explicitly loaded and committed into the firewall's live configuration
- 1.5.12 - Updated script to support certificate-based API authentication to address deprecated KeyGen algorithm warning; added fallback warning for users who have not configured API key certificates
- 1.5.11 - Added new menu option to create or update objects in batches from a file, allowing efficient processing of large object sets with format validation, updates, and commits
- 1.5.10 - Optimized script flow by separating delete, add, and replace operations into distinct tasks with clear user prompts; reverted menu structure to working version 1.5.3 and updated to meet new requirements for improved clarity and audit reporting
- 1.5.9 - Added automatic commit after successful running configuration backup in download_running_config to ensure changes are committed before proceeding
- 1.5.8 - Fixed SyntaxError in add_objects_or_groups by correcting the f-string expression with conflicting quotes, ensuring proper string termination
- 1.5.7 - Reverted to working version 1.5.3 and reapplied changes from 1.5.4 through 1.5.6, ensuring the script compiles and runs on Windows 11 x64, fixing early failure before login prompts; corrected XML parsing in check_object_usage
- 1.5.6 - Fixed potential SyntaxError or runtime issue in add_objects_or_groups by correcting non-ASCII characters in the commit confirmation condition
- 1.5.5 - Fixed SyntaxError in add_objects_or_groups by removing backslash in f-string expression and using alternative string splitting method
- 1.5.4 - Modified report generation to append reports to a single file with timestamps instead of overwriting, for audit purposes
- 1.5.3 - Adjusted running configuration backup filename to be <=32 characters, added options to add new objects and object groups with interactive input and commit confirmation
- 1.5.2 - Added ability to restore running configuration, modified countdown timer to allow restore option, and introduced a menu-driven interface for selecting actions with iterative flow
- 1.5.1 - Enhanced KeyboardInterrupt handling to ensure consistent graceful exit across all user prompts in the new structured flow
- 1.5.0 - Corrected filename to palo_config_change.py and reset version to v1
- 1.4.17 - Implemented structured flow: added backup prompt after login, structured object deletion with policy impact listing, object replacement with sync check, and exit countdown option
- 1.4.16 - Corrected non-batch deletion to use new_objects.txt for replacing old object values instead of a separate object_replacements.txt file
- 1.4.15 - Added option to choose between batch deletion or replacing old object values with new ones without deletion, with case-insensitive Y/N input handling
- 1.4.14 - Fixed error in generate_report where 'new_added' key was accessed unconditionally, causing an unexpected error when processing deletions
- 1.4.13 - Optimized script for bash workflow: pre-optimize objects in the firewall, process deletions in batches, update object values if used in policies, delete if not in use, and update or remove from groups if in groups
- 1.4.12 - Added graceful handling of KeyboardInterrupt (Ctrl+C) during user prompts to exit cleanly with a message
- 1.4.11 - Optimized deletion process by adding prompt to remove object from address group if it is a member, allowing automatic removal and continuation
- 1.4.10 - Fixed error where 'keep_policy' variable was undefined when an object is used only in address groups during deletion
- 1.4.9 - Error was found and fixed
- 1.4.8 - Optimized deletion process by verifying object presence, prompting for per-object deletion confirmation, and saving backup objects and groups in a reusable format
- 1.4.7 - Added support for separate files (objects_to_delete.txt, objects_to_add.txt, objects_to_update.txt) to manage deletions, additions, and value changes
- 1.4.6 - Added checks for object usage in firewall policies, prompted for replacement objects, and managed policy retention or deletion based on user input
- 1.4.5 - Corrected objects_to_delete.txt format to one object name per line and updated script filename to palo_config_change.py format
- 1.4.4 - Added mandatory configuration backup prompt before changes and specified expected format for objects_to_delete.txt
- 1.4.3 - Added functionality to delete specific address objects based on a provided list
- 1.4.2 - Fixed WinError 10038 in is_host_reachable by using context managers for socket handling
- 1.4.1 - Prefixed firewall hostname to running configuration filename (e.g., FW01_running-config_20240101_120000.xml)
- 1.4.0 - Added option to list objects and groups in copyable format for object files (e.g., name,value and group_name,member1;member2)
- 1.3.1 - Modified running config download to append date and time (e.g., running-config_20240101_120000.xml) instead of overwriting
- 1.3.0 - Added option to download current running configuration as running-config.xml
- 1.2.1 - Updated Yes/No prompt to accept Y/y/Yes/N/n/No in any case; corrected to maintain (Yes/No) display with case-insensitive handling
- 1.2.0 - Added support for multiple address types: IP with netmask, IP range, IP wildcard mask, FQDN, IPv6
- 1.1.0 - Added IP address format validation with error flagging in report
- 1.0.0 - Initial version with object parsing in copyable format, version control added

## Repository

- palo_config_change_stable.py (v1.5.13.1) removed; it is in git history. Use palo_config_change.py.
- policy-api: token auth, WORK_DIR path restriction, fail-closed rule validation, no config/response logging.
- config-change-webapp: defusedxml, secure upload names, upload size limit, env-only debug and secret key.
