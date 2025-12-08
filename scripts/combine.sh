#!/bin/bash

# Default values
PATH_DIR="."
OUTPUT_FILE="output.md"
IGNORE_PATTERNS=()

# Function to display help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Combine contents of all files in a directory (including subdirectories) into a single markdown file."
    echo ""
    echo "Options:"
    echo "  -p, --path=<directory>  Specify the directory to scan (default: current directory)"
    echo "  -o, --out=<file>        Specify the output markdown file (default: output.md)"
    echo "  -i, --ignore=<pattern>  Pattern to ignore files/directories (can be used multiple times)"
    echo "  -h, --help              Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 --path=/path/to/dir --out=result.md --ignore='*.log' --ignore='node_modules'"
    exit 0
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -p=*|--path=*) PATH_DIR="${1#*=}" ;;
        -o=*|--out=*) OUTPUT_FILE="${1#*=}" ;;
        -i=*|--ignore=*) IGNORE_PATTERNS+=("${1#*=}") ;;
        -h|--help) show_help ;;
        *) echo "Error: Unknown parameter: $1" >&2; show_help; exit 1 ;;
    esac
    shift
done

# Error checking
# Check if path exists and is a directory
if [ ! -d "$PATH_DIR" ]; then
    echo "Error: Directory '$PATH_DIR' does not exist or is not a directory" >&2
    exit 1
fi

# Check if path is readable
if [ ! -r "$PATH_DIR" ]; then
    echo "Error: Directory '$PATH_DIR' is not readable" >&2
    exit 1
fi

# Check if output file's directory is writable
OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
if [ ! -w "$OUTPUT_DIR" ]; then
    echo "Error: Cannot write to output directory '$OUTPUT_DIR'" >&2
    exit 1
fi

# Check if output file already exists
if [ -f "$OUTPUT_FILE" ]; then
    read -p "Warning: Output file '$OUTPUT_FILE' already exists. Overwrite? (y/n): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Operation cancelled" >&2
        exit 1
    fi
fi

# Create or clear the output file
> "$OUTPUT_FILE" 2>/dev/null || {
    echo "Error: Failed to create/clear output file '$OUTPUT_FILE'" >&2
    exit 1
}

# Function to check if file should be ignored
should_ignore() {
    local file="$1"
    for pattern in "${IGNORE_PATTERNS[@]}"; do
        if [[ "$file" =~ $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Function to process each file
process_file() {
    local file="$1"
    # Skip the output file itself and ignored files
    if [ "$file" != "$OUTPUT_FILE" ] && ! should_ignore "$file"; then
        # Check if file is readable
        if [ -r "$file" ]; then
            echo "## File: $file" >> "$OUTPUT_FILE"
            echo '```' >> "$OUTPUT_FILE"
            cat "$file" >> "$OUTPUT_FILE" 2>/dev/null || {
                echo "Warning: Failed to read file '$file'" >&2
            }
            echo '```' >> "$OUTPUT_FILE"
            echo "" >> "$OUTPUT_FILE"
        else
            echo "Warning: File '$file' is not readable" >&2
        fi
    fi
}

# Export the function and variables so they can be used by find
export -f process_file
export -f should_ignore
export OUTPUT_FILE
export IGNORE_PATTERNS

# Build find command with ignore patterns
FIND_CMD="find \"$PATH_DIR\" -type f"
for pattern in "${IGNORE_PATTERNS[@]}"; do
    FIND_CMD+=" -not -path \"*/$pattern/*\" -not -name \"$pattern\""
done
FIND_CMD+=" -exec bash -c 'process_file \"{}\"' \;"

# Execute find command
eval "$FIND_CMD" 2>/dev/null || {
    echo "Error: Failed to process files in '$PATH_DIR'" >&2
    exit 1
}

echo "All file contents have been combined into '$OUTPUT_FILE'"
