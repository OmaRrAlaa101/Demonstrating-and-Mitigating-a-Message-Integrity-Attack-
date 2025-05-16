import hmac
import hashlib

SECRET_KEY = b'supersecretkey'

def generate_mac(message: bytes) -> str:
    return hmac.new(SECRET_KEY, message, hashlib.md5).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    expected_mac = generate_mac(message)
    return mac == expected_mac

def main():
    message = b"amount=100&to=alice"
    mac = generate_mac(message)

    print("=== Secure Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")

    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("MAC verified successfully. Message is authentic.\n")

    print("--- Verifying forged message from attacker ---")
    try:
        with open("forged_input.txt", "rb") as f:
            forged_message = f.readline().strip()
            forged_mac = f.readline().strip().decode()

        if verify(forged_message, forged_mac):
            print("MAC verified successfully (UNEXPECTED - Attack Succeeded!)")
        else:
            print("MAC verification failed (attack blocked, HMAC worked).")
    except Exception as e:
        print("Error reading forged message:", e)

if _name_ == "_main_":
    main()