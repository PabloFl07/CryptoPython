# Length Extension Attack

A Length Extension Attack (Ataque de Extensión de Longitud) is a vulnerability that affects certain cryptographic hash functions based on the Merkle–Damgård construction (such as MD5, SHA-1, and SHA-256). 

This type of attack allows an attacker who knows a hash value $H(m_1)$ and the length of the original input message $m_1$—without knowing the secret content of $m_1$ itself—to compute $H(m_1 \,\vert{}\vert{}\, \text{padding} \,\vert{}\vert{}\, m_2)$ for any arbitrary message $m_2$.  

This security flaw occurs primarily when simple constructions like Hash(Secret || Message) are used for authentication instead of secure Message Authentication Codes (MACs) such as HMAC.  

### Additional Content

The primary way to mitigate this type of attack is to use **[HMAC](/pocs/hashing/HMAC.md)**, the standard for message authentication. Check out its own PoC

## Attack Vector  
  
An attacker intercepts a valid data payload alongside its valid hash signature from a vulnerable Web aplication, API, protocol... that authenticate incoming HTTP parameters, cookies, or payloads by calculating Hash(SecretKey + UserData)

- Exploitation Flow:
    1. The attacker observes a legitimate message (e.g., user=guest) and its corresponding signature/hash.   
    2. By loading the output hash into a custom hash engine as its initial internal state, the attacker bypasses the requirement of knowing the SecretKey.   
    3. The attacker appends malicious parameters (e.g., &role=admin) along with the computed glue/padding bytes.   
    4. The application recalculates Hash(SecretKey + UserData + Padding + MaliciousData) and finds a perfect match, authorizing the request.


## Length Extension Attack Step-by-Step

### ⚠️ Note on implementation

To successfully execute this attack, you must extract the 32-bit internal records from the intercepted hexadecimal hash and manually feed them into a custom block compression algorithm.

This demo naively recalculates `hashlib.sha256(...)` After all, the goal is not to teach how to exploit the vulnerability.

--- 

The Setup:

- Secret Key: `SECRET` (6 characters)
- Original Message: `user=guest` (10 characters)
- Original Hash: `ae4f...` (The result of SHA1("SECRETuser=guest"))


### Step 1: Guessing the Secret Length

The attacker doesn't need the secret key, but **they do need to know its length** to calculate the correct padding. If the length is unknown, they can simply iterate (brute force) through possible lengths (e.g., 1 to 64 bytes). For each length, they generate a payload and test it against the application. If the **application accepts the request**, the attacker has found the correct length.

### Step 2: Reconstructing the Original Padding

Hash functions require padding to align the message to block boundaries. For SHA-1, the padding for the message SECRETuser=guest (16 bytes total) would look something like this in hex:


```
80 00 00 00 ... 00 00 00 00 00 00 00 80
```

- `0x80`: The '1' bit followed by zeros in byte form.
- `0x00`: Null bytes to fill the block.
- `0x80`: The length of the original message in bits (16 bytes * 8 = 128 bits, which is 0x80 in hex).

### Step 3: Extending the Hash

The attacker takes the original hash value (`ae4f...`) and uses it to initialize the state of their own SHA-1 engine. They then **"feed" their malicious data (`&role=admin`) into the engine**. The engine **continues from where the previous hash left off**. The resulting new hash is a valid signature for the following combined message:

```
SECRET + user=guest + [Padding] + &role=admin
```

The application, when it receives the request, will take the SecretKey, append the attacker's provided message (user=guest + [Padding] + &role=admin), and calculate the hash. Because the attacker correctly included the original padding in the middle of the string, the application's calculation will match the attacker's forged hash.


## Real-World Case and Impact

Length extension attacks are not just theoretical. One of the most famous examples occurred in 2009 when security researchers discovered that the Flickr API was vulnerable. Flickr used a signed_api_key + arguments construction to authenticate API calls. This allowed anyone to take a signed request and append their own arguments, effectively gaining unauthorized access to user data and performing actions on behalf of users.

The impact of these attacks includes:

- **Authentication Bypass**: Gaining access to restricted accounts or administrative panels.
- **Data Tampering**: Modifying transaction amounts, user roles, or file paths in signed requests.
- **Privilege Escalation**: Elevating a standard user token to an administrator token.


## Alternatives

Algorithms that do not use the Merkle-Damgård construction are inherently immune to this attack.

- **SHA-3** : Uses a "Sponge construction." It is immune to length extension attacks by design because the internal state is much larger than the output hash.
- **BLAKE2**: While extremely fast and secure, BLAKE2 also includes built-in protections against length extension.
- **SHA-512/256**: This is a truncated version of SHA-512. Because the output is a truncated version of the internal state, an attacker cannot easily reconstruct the full state needed to extend the hash.


### Credits

https://blogs.jsmon.sh/what-is-length-extension-attack-ways-to-exploit-examples-and-impact/