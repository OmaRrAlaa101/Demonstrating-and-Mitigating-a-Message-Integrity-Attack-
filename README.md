Background Study 
1. What is a MAC and its purpose in data 
integrity/authentication? 
A Message Authentication Code (MAC) is a cryptographic checksum that provides: 
• Data integrity: Ensures the message hasn't been altered 
• Authentication: Verifies the message comes from the claimed sender 
• Non-repudiation: Prevents senders from denying they sent the message 
MACs use a secret key shared between communicating parties. Common constructions 
include: 
• HMAC (Hash-based MAC) 
• CBC-MAC (Block cipher-based) 
• KMAC (SHA-3 based) 
2. Length Extension Attack in MD5/SHA1 
This attack exploits the Merkle-Damgård construction used in hash functions like MD5 and 
SHA-1. The vulnerability occurs because: 
1. Hash functions process input in fixed-size blocks 
2. The internal state (intermediate hash value) can be predicted 
3. Given H(message), an attacker can compute H(message || padding || extension) 
without knowing the original message 
For MAC = hash(secret || message): 
• Attacker can extend the message while maintaining a valid MAC 
• The secret key's position makes the MAC vulnerable 
3. Why MAC = hash(secret || message) is insecure 
This naive construction is vulnerable because: 
1. Length extension vulnerability: As demonstrated in our attack 
2. Collision attacks: MD5/SHA-1 are no longer collision-resistant 
3. No key separation: Keys and data are concatenated without proper domain 
separation







Mitigation Write-Up: Preventing Length 
Extension Attacks 
1. Overview of the Vulnerability 
In our initial implementation (server.py), we used a naive MAC construction: 
![image](https://github.com/user-attachments/assets/5cbd8789-1f08-4ecf-b1ea-3c9b76caf286)
This approach is vulnerable to length extension attacks because: 
• MD5 follows the Merkle-Damgård construction, allowing attackers to extend a 
hash if they know the original message and MAC. 
• The secret key is prepended, meaning the attacker can compute a valid MAC for 
message + malicious_extension without knowing the key. 
1.1 Attack Demonstration 
Our client.py successfully performed the attack: 
1. Intercepted a valid (message, MAC) pair (amount=100&to=alice, 
614d28d808af46d3702fe35fae67267c). 
2. Appended &admin=true and computed a new valid MAC using hashpumpy. 
3. The forged message was accepted by the vulnerable server. 
This proves that H(secret || message) is cryptographically insecure.
![image](https://github.com/user-attachments/assets/d3831d36-0f0c-401a-83c8-ea158523cba0)
2. Secure Implementation Using HMAC 
We mitigated the attack by replacing the insecure MAC with HMAC-MD5 in 
secure_server.py: 
2.1 Key Changes
   ![image](https://github.com/user-attachments/assets/5855676d-795b-4ebc-9149-38b9f7fa73b3)
   2.2 Why HMAC Works 
HMAC prevents length extension attacks because: 
1. Nested Hashing: 
a. The key is mixed with ipad (inner padding) and opad (outer padding). 
b. The structure H(K ⊕ opad || H(K ⊕ ipad || message)) breaks 
linearity. 
2. No Predictable State: 
a. Even if MD5 is used, the double hashing prevents extending the message. 
3. Standardized Security: 
a. HMAC is provably secure (RFC 2104) even if the underlying hash has 
weaknesses. 
2.3 Testing the Secure Server 
When the same forged message from client.py was sent to secure_server.py: 
• The MAC verification failed, confirming HMAC’s resistance to length extension. 
• Only legitimately signed messages (amount=100&to=alice) were accepted.
![image](https://github.com/user-attachments/assets/384e0253-2c17-4d3a-b6d7-3a8fc2de50ec)
3. Conclusion 
Key Takeaways 
✅ Never use H(secret || message) – It is vulnerable to length extension. 
✅ Always use HMAC – Even with weak hashes (like MD5), HMAC provides security. 
✅ Prefer modern hashes – HMAC-SHA256 is the gold standard. 
✅ Defense in depth – Combine HMAC with input validation and constant-time checks. 
Final Notes 
Our mitigation (secure_server.py) successfully blocked the attack while maintaining 
compatibility with legitimate messages. This demonstrates: 
• The importance of using well-vetted cryptographic constructions. 
• How theoretical attacks become practical threats.



