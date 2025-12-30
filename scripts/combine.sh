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
    echo "  -i, --ignore=<pattern>  Pattern to ignore files/directories (Regex supported)"
    echo "  -h, --help              Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 --path=src --out=result.md --ignore='node_modules' --ignore='\.log$'"
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
if [ ! -d "$PATH_DIR" ]; then
    echo "Error: Directory '$PATH_DIR' does not exist" >&2
    exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT_FILE")
if [ ! -w "$OUTPUT_DIR" ] && [ ! -w "." ]; then
    echo "Error: Cannot write to output directory" >&2
    exit 1
fi

# Create/Clear output file
> "$OUTPUT_FILE"

# Function to check if file should be ignored
should_ignore() {
    local file="$1"
    # Check output file
    if [[ "$file" == *"$OUTPUT_FILE" ]]; then return 0; fi

    # Check ignore patterns
    for pattern in "${IGNORE_PATTERNS[@]}"; do
        # Use simple string match or regex
        if [[ "$file" =~ $pattern ]]; then
            return 0
        fi
    done
    return 1
}

# Check if file is binary
is_binary() {
    local file="$1"
    # Cách 1: Dùng grep để check NULL byte (phổ biến nhất)
    if grep -Iq . "$file" 2>/dev/null; then
        return 1 # Là text
    else
        # Nếu file rỗng thì coi là text, còn nếu có content mà grep -I fail thì là binary
        if [ -s "$file" ]; then
             return 0 # Là binary
        fi
        return 1 # File rỗng, coi là text
    fi
}

echo "Scanning directory: $PATH_DIR"
echo "Output file: $OUTPUT_FILE"

# Process files using find + while loop (to keep array scope valid)
# -print0 handles filenames with spaces correctly
find "$PATH_DIR" -type f -print0 | while IFS= read -r -d '' file; do

    # 1. Check Ignore Patterns
    if should_ignore "$file"; then
        continue
    fi

    # 2. Check Binary Files (Images, compiled files, etc.)
    if is_binary "$file"; then
        echo "Skipping binary file: $file"
        continue
    fi

    # 3. Write to output
    echo "Processing: $file"
    echo "## File: $file" >> "$OUTPUT_FILE"
    echo '```' >> "$OUTPUT_FILE"
    cat "$file" >> "$OUTPUT_FILE"
    echo -e "\n\`\`\`\n" >> "$OUTPUT_FILE"

done

echo "Done! All contents combined into '$OUTPUT_FILE'"

