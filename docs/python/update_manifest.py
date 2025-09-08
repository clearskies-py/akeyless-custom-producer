# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "clear-skies>=2.0",
# ]
# ///
import json
import os
import re
import sys
import clearskies

ManifestEntry = dict[str, str]
ManifestData = list[ManifestEntry]


def update_manifest(input_output: clearskies.input_outputs.Cli) -> None:
    """
    Sanitizes, checks, updates, and sorts a manifest.json file.
    The clearskies.contexts.Cli context will pass the command-line arguments
    directly to these parameters after validation and applying defaults from the schema.
    """
    args = json.loads(input_output.get_body())
    manifest_file: str = args.get("manifest_file", "manifest.json")
    pyproject_file: str = args.get("pyproject_file", "pyproject.toml")
    modules_location: str = args.get("modules_location", "modules")

    # Step 1: Read and sanitize the manifest.
    manifest_data: ManifestData = _read_and_sanitize_manifest(manifest_file)

    # Step 2: Fetch module name and generate URL.
    module_name: str | None = _get_module_name_from_pyproject(pyproject_file)
    if not module_name:
        print(f"Error: Could not find 'name' in {pyproject_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Found module name: {module_name}")
    module_url: str = f"/{modules_location.strip('/')}/{module_name.lower().replace(' ', '-')}/"

    # Step 3: Find existing module to update its URL, or add it if it's new.
    print("Checking for existing module...")
    existing_module: ManifestEntry | None = next(
        (module for module in manifest_data if module.get("name") == module_name), None
    )

    if existing_module:
        if existing_module.get("url") != module_url:
            print(f"Module '{module_name}' found. Updating outdated URL.")
            existing_module["url"] = module_url
        else:
            print(f"Module '{module_name}' already exists with the correct URL.")
    else:
        print(f"Module not found. Adding '{module_name}' to the manifest.")
        manifest_data.append({"name": module_name, "url": module_url})

    # Step 4: Sort the final list by name.
    print("Sorting the manifest...")
    sorted_manifest: ManifestData = sorted(manifest_data, key=lambda x: x["name"])

    # Step 5: Write the updated and sorted data back to the file.
    _write_manifest(manifest_file, sorted_manifest)

    print("Manifest update complete.")
    sys.exit(0)


def _read_and_sanitize_manifest(manifest_file: str) -> ManifestData:
    """
    Reads the manifest file, sanitizes it, and returns a clean list of module objects.
    """
    if not os.path.exists(manifest_file) or os.path.getsize(manifest_file) == 0:
        print("Manifest file is missing or empty. Starting with an empty list.")
        return []

    print("Sanitizing manifest file...")
    try:
        with open(manifest_file, "r") as f:
            data: list | dict = json.load(f)
        if not isinstance(data, list):
            print(
                "Warning: Manifest content is not a list. Starting fresh.",
                file=sys.stderr,
            )
            return []

        # Ensure every item in the list is a dictionary with a 'name' key
        clean_data: ManifestData = [item for item in data if isinstance(item, dict) and "name" in item]
        print("Sanitization successful.")
        return clean_data
    except json.JSONDecodeError:
        print(
            f"ERROR: '{manifest_file}' contains invalid JSON and could not be parsed.",
            file=sys.stderr,
        )
        print("Please fix the file content manually.", file=sys.stderr)
        sys.exit(1)


def _get_module_name_from_pyproject(pyproject_file: str) -> str | None:
    """
    Finds the project name from a pyproject.toml file.
    """
    if not os.path.exists(pyproject_file):
        return None
    with open(pyproject_file, "r") as f:
        for line in f:
            match = re.match(r'^\s*name\s*=\s*"(.*?)"', line)
            if match:
                return match.group(1)
    return None


def _write_manifest(manifest_file: str, data: ManifestData):
    """
    Writes the provided data to the manifest file.
    """
    try:
        with open(manifest_file, "w") as f:
            json.dump(data, f, indent=2)
    except IOError as e:
        print(f"ERROR: Could not write to manifest file: {e}", file=sys.stderr)
        sys.exit(1)


# Define the schema using a class, which is the standard, modern pattern.
class CliInputSchema(clearskies.Schema):
    pyproject_file = clearskies.columns.String(default="pyproject.toml")
    manifest_file = clearskies.columns.String(default="manifest.json")
    modules_location = clearskies.columns.String(default="modules")


# Pass an instance of our schema class to the Callable endpoint.
endpoint = clearskies.endpoints.Callable(
    to_call=update_manifest,
    input_schema=CliInputSchema,
)

# ...and wrap the endpoint in the Cli context.
cli = clearskies.contexts.Cli(endpoint)

if __name__ == "__main__":
    # The cli() call will now use the defaults from the input_schema
    # for any arguments that are not provided.
    cli()
