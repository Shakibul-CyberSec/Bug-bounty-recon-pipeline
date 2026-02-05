#!/bin/bash

# ✅ Default input file (can be overridden with -f)
input_file=""
output_dir="filtered-urls"  # Default output directory

# ✅ List of sensitive extensions
extensions=(
  xls xml xlsx json pdf sql doc docx pptx txt zip tar.gz tgz bak 7z rar
  log cache secret db backup yml gz config csv yaml md md5 exe dll bin
  ini bat sh tar deb rpm iso img apk msi dmg tmp crt pem key pub asc
)

# ✅ Function to show usage
function usage() {
    echo "Usage: $0 -f <input_file> [-o <output_dir>]"
    echo "Options:"
    echo "  -f, --file      Input file containing URLs (required)"
    echo "  -o, --output    Output directory (default: filtered-urls)"
    exit 1
}

# ✅ Parse flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -f|--file) input_file="$2"; shift ;;
        -o|--output) output_dir="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "❌ Error: Unknown parameter passed: $1"; usage ;;
    esac
    shift
done

# ✅ Check if input file provided
if [[ -z "$input_file" ]]; then
    echo "❌ Error: Input file not provided!"
    usage
fi

# ✅ Check if file exists
if [[ ! -f "$input_file" ]]; then
    echo "❌ Error: File '$input_file' not found!"
    exit 1
fi

# ✅ Create output folder
mkdir -p "$output_dir"

# ✅ Filter and process
echo -e "\n🔍 Deduplicating and filtering URLs from '$input_file'..."
deduped_urls=$(cat "$input_file" | uro)

for ext in "${extensions[@]}"; do
    echo "➡️  Searching for .$ext ..."
    echo "$deduped_urls" | grep -Ei "\.${ext}\b" > "$output_dir/${ext}.txt"
done

echo -e "\n✅ All done! Output saved in '$output_dir/' 🎉"
