## Instruction for Speed test comparison

## Test case

We will use `\time -v` running in bash to record elapsed time and memory on multi secrets scanners.
Command template:

- rayloc scan <dir> --silent
- trufflehog filesystem <dir> --no-verification --no-update | rg "finished scanning"
- gitleaks dir <dir>
- betterleaks fs <dir> --silent

These tools are installed in ~/.local/bin and loaded with PATH, so you can call them with name

# data

We will do scan on code repository placed in `/home/liam/Dev/installation`
Target project directory (dir):

- llama.cpp/
- vllm/
- claude-code
- opencode
- ponytail
- OpenShell
- paperclip
- hindsight

# Report

Collect data of each runs for processed volume (bytes into megabytes), elapsed time, CPU usage (Percent of CPU this job got), memory (maximum resident set size)

Then create a pivot table for these 3 aspects across scan targets: Avg Elapsed time per MB, avg CPU per MB, avg memory MB in which MB is the megabytes of processed volume. With tools name as column (in correct order above), and 3 aspect, each is on a row
