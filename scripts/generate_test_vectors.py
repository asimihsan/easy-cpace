#!/usr/bin/env python3
import sys
import textwrap
from pathlib import Path

# Appendix B.  Test vectors
# B.1.  Test vector for CPace using group X25519 and hash SHA-512s
# B.1.1.  Test vectors for calculate_generator with group X25519
B_1_1_1_TEST_VECTORS: dict[str, str] = {
    "H": "SHA-512",
    "H.s_in_bytes": 128,
    "PRS": "50617373776F7264",
    "ZPAD length": 109,
    "DSI": "4350616365323535",
    "CI": "6F630B425F726573706F6E6465720B415F696E69746961746F72",
    "sid": "7E4B4791D6A8EF019B936C79FB7F2C57",
    # Renamed key for valid C identifier generation
    "generator_input_string": "0843506163653235350850617373776F72646D000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001A6F630B425F726573706F6E6465720B415F696E69746961746F72107E4B4791D6A8EF019B936C79FB7F2C57",
    "hash_generator_string": "92806DC608984DBF4E4AAE478C6EC453AE979CC01ECC1A2A7CF49F5CEE56551B",
    "decoded_field_element_of_255_bits": "92806DC608984DBF4E4AAE478C6EC453AE979CC01ECC1A2A7CF49F5CEE56551B",
    "generator_g": "64E8099E3EA682CFDC5CB665C057EBB514D06BF23EBC9F743B51B82242327074",
    # Removed descriptive Ya/Yb keys that clash with simpler ones below
    # "Ya = X25519(xa, g)": "...",
    # "Yb = X25519(xb, g)": "...",
}

# B.1.2.  Test vector for message from A
# B.1.3.  Test vector for message from B
# B.1.4.  Test vector for secret points K
# B.1.5.  Test vector for ISK calculation initiator/responder
# B.1.6.  Test vector for ISK calculation parallel execution
# B.1.7.  Test vector for optional output of session id
B_1_9_TEST_VECTORS: dict[str, str] = {
    "PRS": "50617373776F7264",
    "CI": "6F630B425F726573706F6E6465720B415F696E69746961746F72",
    "sid": "7E4B4791D6A8EF019B936C79FB7F2C57",
    "g": "64E8099E3EA682CFDC5CB665C057EBB514D06BF23EBC9F743B51B82242327074",
    # "ya": "21B4F4BD9E64ED355C3EB676A28EBEDAF6D8F17BDC365995B319097153044080", # Removed lowercase duplicate
    "ADa": "414461",
    "Ya": "1B02DAD6DBD29A07B6D28C9E04CB2F184F0734350E32BB7E62FF9DBCFDB63D15",
    # "yb": "848B0779FF415F0AF4EA14DF9DD1D3C29AC41D836C7808896C4EBA19C51AC40A", # Removed lowercase duplicate
    "ADb": "414462",
    "Yb": "20CDA5955F82C4931545BCBF40758CE1010D7DB4DB2A907013D79C7A8FCF957F",
    "K": "F97FDFCFFF1C983ED6283856A401DE3191CA919902B323C5F950C9703DF7297A",
    # Added missing ISK Input String from B.1.5
    "ISK_Input_String": "0C43506163653235355F49534B107E4B4791D6A8EF019B936C79FB7F2C5720F97FDFCFFF1C983ED6283856A401DE3191CA919902B323C5F950C9703DF7297A201B02DAD6DBD29A07B6D28C9E04CB2F184F0734350E32BB7E62FF9DBCFDB63D15034144612020CDA5955F82C4931545BCBF40758CE1010D7DB4DB2A907013D79C7A8FCF957F03414462",
    "ISK_IR": "A051EE5EE2499D16DA3F69F430218B8EA94A18A45B67F9E86495B382C33D14A5C38CECC0CC834F960E39E0D1BF7D76B9EF5D54EECC5E0F386C97AD12DA8C3D5F",
    "ISK_SY": "5CC27E49679423F81A37D7521D9FB1327C840D2EA4A1543652E7DE5CABB89EBAD27D24761B3288A3FD5764B441ECB78D30ABC26161FF45EA297BB311DDE04727",
    "sid_output_ir": "F7AE11AC3EE85C3C42D8BD51BA823FBE17158F43D34A1296F1CB2567BCC71DC8B201A134B566B468AAD8FD04F02F96E3CAF9D5601F7ED760A0A951A5A861B5E7",
    "sid_output_oc": "A38389E34FA492788C1DF43B06B427710491174E53C33B01362A490D116FE1B7E870AA6E2A7FC018725E3B7F969F7508042E44CD3863F39AA75026A190D1902B",
    # Added missing scalar 's' from B.1.10
    "s": "0300000000000000000000000000000000000000000000000000000000000000",
}

# B.1.10.  Test vectors for G_X25519.scalar_mult_vfy: low order points
B_1_10_TEST_VECTORS: dict[str, str] = {
    "Invalid Y0": "0000000000000000000000000000000000000000000000000000000000000000",
    "Invalid Y1": "0100000000000000000000000000000000000000000000000000000000000000",
    "Invalid Y2": "ECFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
    "Invalid Y3": "E0EB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B800",
    "Invalid Y4": "5F9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F1157",
    "Invalid Y5": "EDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
    "Invalid Y6": "DAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "Invalid Y7": "EEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",
    "Invalid Y8": "DBFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "Invalid Y9": "D9FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    "Invalid Y10": "CDEB7A7C3B41B8AE1656E3FAF19FC46ADA098DEB9C32B1FD866205165F49B880",
    "Invalid Y11": "4C9C95BCA3508C24B1D0B1559C83EF5B04445CC4581C8E86D8224EDDD09F11D7",
}

# Combine all vector dictionaries
ALL_VECTORS = {}
ALL_VECTORS.update(B_1_1_1_TEST_VECTORS)
ALL_VECTORS.update(B_1_9_TEST_VECTORS)
# Handle potential duplicates if necessary, though keys seem unique here
# For B.1.10, map the descriptive key to a simpler variable name
for key, value in B_1_10_TEST_VECTORS.items():
    # e.g., "Invalid Y0" -> "U0"
    var_name = key.replace("Invalid Y", "U")
    ALL_VECTORS[var_name] = value


# --- Configuration ---
HEADER_GUARD = "GENERATED_RFC_VECTORS_H"
OUTPUT_VAR_PREFIX = "RFC_B1"


# --- Helper Functions ---
def parse_hex_string(hex_str):
    """Cleans up and converts a potentially multi-line hex string to bytes."""
    return bytes.fromhex("".join(hex_str.split()))


def format_c_array(name, data):
    """Formats bytes into a C unsigned char array string."""
    if not data:
        return f"const unsigned char {name}[] = {{}};\nconst size_t {name}_LEN = 0;"

    hex_vals = [f"0x{b:02x}" for b in data]
    # Wrap lines nicely
    wrapper = textwrap.TextWrapper(
        width=100, subsequent_indent="    ", initial_indent="    "
    )
    wrapped_hex = wrapper.fill(", ".join(hex_vals))

    return f"const unsigned char {name}[] = {{\n{wrapped_hex}\n}};\nconst size_t {name}_LEN = sizeof({name});"


def sanitize_key_to_c_var(key: str) -> str:
    """Converts a dictionary key into a suitable C variable name."""
    # Replace problematic characters with underscores
    sanitized = key.replace(" ", "_").replace(".", "_").replace("(", "").replace(")", "").replace("/", "_").replace(",", "_")
    # Ensure it starts with a letter or underscore (should be fine here)
    # Convert to uppercase
    return sanitized.upper()


# --- Main Script Logic ---
def main(output_path: str):
    # Generate Header File Content
    header_content = f"""\
// Automatically generated by {Path(__file__).name}
// DO NOT EDIT MANUALLY!

#ifndef {HEADER_GUARD}
#define {HEADER_GUARD}

#include <stddef.h> // For size_t
#include <stdint.h> // For uint8_t

// --- RFC Appendix B.1 Test Vectors (Embedded from script dictionaries) ---

"""
    errors = False
    # Iterate through the combined dictionary
    for key, hex_value in sorted(ALL_VECTORS.items()):
        # Skip non-hex string values (like 'H', 'H.s_in_bytes', 'ZPAD length')
        if not isinstance(hex_value, str) or not all(c in '0123456789abcdefABCDEF' for c in hex_value):
            # print(f"Skipping non-hex value for key: {key}", file=sys.stderr)
            continue

        c_var_name = sanitize_key_to_c_var(key)
        c_name = f"{OUTPUT_VAR_PREFIX}_{c_var_name}"

        try:
            byte_data = parse_hex_string(hex_value)
            header_content += format_c_array(c_name, byte_data) + "\n\n"
        except ValueError as e:
            print(f"Error parsing hex string for key '{key}': {e}", file=sys.stderr)
            errors = True

    if errors:
        print("Errors occurred during hex parsing. Header file might be incomplete or incorrect.", file=sys.stderr)
        # Decide if you want to exit here or write a potentially broken file
        # sys.exit(1) # Optional: exit on parsing error

    header_content += f"#endif // {HEADER_GUARD}\n"

    # Write Header File
    try:
        Path(output_path).write_text(header_content)
        print(f"Successfully generated '{output_path}'")
    except Exception as e:
        print(f"Error writing output file '{output_path}': {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            f"Usage: {sys.argv[0]} <output_c_header_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    output_file = sys.argv[1]
    # No input file needed, main now uses internal dictionaries
    main(output_file)
