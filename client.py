import hashpumpy
import hashlib
import hmac

# Emulate verification from server.py (insecure)
def weak_verify(message: bytes, mac: str, secret_key: bytes) -> bool:
    expected_mac = hashlib.md5(secret_key + message).hexdigest()
    return mac == expected_mac

# Emulate verification from secure_server.py (using HMAC)
def hmac_verify(message: bytes, mac: str, secret_key: bytes) -> bool:
    expected_mac = hmac.new(secret_key, message, hashlib.md5).hexdigest()
    return mac == expected_mac

def main():
    original_message = "amount=100&to=alice"
    original_mac = "614d28d808af46d3702fe35fae67267c"  # Replace with the actual MAC from server.py
    data_to_append = "&admin=true"
    key_length = 16  # Try other values like 14–20 if needed

    # Secret key used only for simulating server-side verification
    SECRET_KEY = b'supersecretkey'

    # Perform length extension attack
    new_mac, new_message = hashpumpy.hashpump(original_mac, original_message, data_to_append, key_length)

    print("=== Server Simulation ===")
    print(f"Original message: {original_message}")
    print(f"MAC: {original_mac}")

    print("\n--- Verifying legitimate message ---")
    if weak_verify(original_message.encode(), original_mac, SECRET_KEY):
        print("MAC verified successfully. Message is authentic.")

    print("\n--- Verifying forged message on WEAK server ---")
    if weak_verify(new_message, new_mac, SECRET_KEY):
        print("MAC verified successfully (unexpected). Attack succeeded.")
    else:
        print("MAC verification failed. Attack blocked.")

    print("\n--- Verifying forged message on SECURE server ---")
    if hmac_verify(new_message, new_mac, SECRET_KEY):
        print("MAC verified successfully (unexpected). HMAC validation failed.")
    else:
        print("MAC verification failed. HMAC prevented the attack.")

    print(f"\nForged message: {new_message}")
    print(f"Forged MAC: {new_mac}")

    # Save forged data for use by server scripts
    with open("forged_input.txt", "wb") as f:
f.write(new_message + b"\n")
        f.write(new_mac.encode() + b"\n")

    main()