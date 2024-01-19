# **4.1 Mechanism Description**

## Introduction
For this phase, our team has planned and employed various cryptographic mechanisms and protocols to address the concerns of threats 5-7. The goal of these mechanisms and protocols is to ensure the security of the system by preventing message reorder, replay, or modification, resource leakage, and token theft. In order to achieve this we have implemented the 


 ### **Threat 5 -> Message Reorder, Replay, or Modification**
**Description:** This threat is when the messages sent between the user and server might be reordered, saved for later replay, or modified by an active attacker. With these man-in-the-middle attacks the attacker can impersonate the user and send messages to the server. This can be used to send malicious messages to the server or to steal information from the server. If any of these are detected we will terminate the client/server connection.

**Example:** If Alice is sending a message to Bob, an attacker can intercept the message and send it to Bob. Bob will think that the message is from Alice and will respond to the attacker. The attacker can then modify the message and send it to Alice. Alice will think that the message is from Bob and will respond to the attacker. This can be used to steal information from Alice and Bob or to send malicious messages to Alice and Bob.

**Mechanism:** Session Token with Message Authentication Code 


We already have begun to protect against these types of attacks through our use of the D-H key exchange. To expand on this and prevent further attacks we can use the idea of a session token. We will use a signed Diffie Hellman key exchange to protect against active attacks. When the client connects to the server, it will send their DH public key signed with their private key and the authentication server's public key. The client will need to have a public key already which we have incorporated in phase 3. The server will then verify the signature of the client's DH public key ensuring the key is coming from the intended sender. The server will send back its own DH public key, signed with its own private key and the client's public key. As already implemented, the client will verify that signature ensuring the server is authentic. 

For our HMAC, instead of generating a second DH key, we will use the client's RSA private key to sign the HMAC. We will use this second key for the HMAC and not the same one for the encryption after DH. When sending a message, the HMAC will be appended and the recipient will use their HMAC key to compute and verify if they match or not. This will ensure that the message has not been modified. Furthermore, we will also track each message using sequence numbers to ensure that messages are not replayed. We will check if the numbers are increasing by comparing them to the previous number. If there are duplicates or the number is not increasing, we will terminate the connection. 


**Argument:** By combining the signed Diffie-Hellman key exchange with the HMAC and sequence numbers, we can ensure that the messages are not reordered, replayed, or modified. The signed Diffie-Hellman key exchange ensures that the messages are coming from the intended sender. The HMAC ensures that the message has not been modified. The sequence numbers ensure that the messages are not replayed. By combining these three mechanisms we can ensure that the messages are not reordered, replayed, or modified.

### **Threat 6 -> Resource Leakage**
**Description:** In this phase host servers are untrusted and therefore can leak resources to unauthorized users. To prevent this we will implement a mechanism to only allow users with the correct permissions to access the resources. This will also require us to track and revoke access to resources when a user is removed from a group.

**Example:** Say Bob is in a group with Alice, Rob, and Joe. Bob is kicked out of the group and is no longer a member. Bob still has access to the resources in the group and can leak them to unauthorized users because the keys used to encrypt the resources are still valid and if they are not renewed and refreshed, Bob will still have access to the resources allowing him to leak them.

**Mechanism:** Group-Specific Keys

For this mechanism, each group will have their own key. When a resource is created it will be encrypted using that group's key. Therefore, only the members of that group have the ability to successfully decrypt and access the resource. If a member is kicked out or removed, it will regenerate the key for the current remaining members which also removes the ability for the kicked-out member to leak the resources.

We will not re-encrypt old resources if a member is kicked out since we assume that the old users have already seen and downloaded the file. Every new file after that removal will have a new key and the kicked-out user cannot decrypt it. We will store the group keys on the authentication server. For this system, whenever the client logs in if they are not currently online, we will get all the keys for the group and update them. If the client is offline, nothing will happen until they log in again. We will also implement a pulling system where every time a user attempts to upload it will "pull" and check the current token to ensure that the user is still a member of the group and has the respective key needed. We will keep track of every key ever used for a group and each key will have a respective version number that will not be encrypted. This will tell us what key version number to use. We will use a list to keep track of the keys and the version numbers. The list will be sorted by the version number and the highest version number will be the current key. When a user is kicked out, we will increment the version number and generate a new key. We will then add the new key to the list and so this way each member will have the same list of keys and the same version number and any kicked-out member will only have access to the keys it was present for but will not be able to use them to decrypt new resources.


**Argument:** By using group-specific keys, we can ensure that only the members of the group have access to the resources. If a member is kicked out or removed, the key will be regenerated for the remaining members which will remove the ability for the kicked-out member to leak the resources. Each new key will be generated by hashing the previous key and this will ensure any user who has been kicked out cannot get future keys and only have the past keys they were present for.

### **Threat 7 -> Token Theft**
**Description:** In this threat, a host server may steal a token used by one of its clients and try to pass it off to another user. This can be used to impersonate the user and gain access to their resources. We will implement a mechanism to ensure any stolen tokens are only usable on the server where the theft took place. 

**Example:** If Bob is using a host server and the host server steals his token, the host server can then use that token on a different server to impersonate Bob without him knowing. 

**Mechanism:** Server-Specific Token 

For this mechanism, we will request a different token for every host server a client may want to connect to. To do this, we will request a token from the authentication server, and in this token we will bind the information about the server such as the ip address and port. The host server will check that token and check for a mismatch based on its own server information and the one presented on the key. Furthermore, we will also need the authentication server to check the token the host server is using is actually intended for it. Simply put, whenever the client requests a token we will get one for the authentication server and one for the host server. If there is any mismatch in the server information the client will not be connected. 


**Argument:** By implementing a server-specific token, we can ensure that any stolen tokens are only usable on the server where the theft took place. This will prevent token theft by validating the tokens each server sends out with the respective server information. This will show us if there is a mismatch and that someone may have stolen a token and is trying to use it on a different server.




## Conclusion: 

In conclusion, we have further secured our system by protecting and implementing against threats 5-7. We have implemented a session token with a message authentication code to protect against active attacks implemented group-specific keys to protect against resource leakage and have implemented server-specific tokens to protect against token theft. For this phase, a lot of the work needed to protect against these new threats was essentially a revamp and upgrade to the old systems we had implemented for threats 1-4. There were some ideas we decided to chalk due to uncertainty and confidence in our ability to do it successfully. For example, we were going to use Lamport OTP scheme to track and manage our group-specific keys, but the chain idea stressed us out, and decided to downscale the idea into a list of keys and version numbers. 

Luckily, from our implementations in phase 3, we had already almost protected against token theft but only needed to add in an extra layer where we verify and check for a mismatch in the server information between the host server, and the authentication server checking the host server ensuring the token is being used for what it is intended to be used for. For threat 5, we had to upgrade our diffie-hellman key exchange and make it signed, as well as add an HMAC to verify the integrity of the messages. Furthermore, we also began tracking sequence numbers to protect against re-order attacks. Altogether, by upgrading to a signed Diffie-hellman key exchange with an HMAC and sequence numbers, creating and managing group-specific keys, and checking for server-information mismatch in the tokens, we have successfully protected against threats 5-7. 

We have also made sure not to retract any progression from our threats 1-4. We still authenticate users, verify and use challenges to check for token modification, check for unauthorized host servers and encrypt all messages sent. 

Finally, we added an extra credit feature where we now have tokens that expire after 'x' amount of time. This feature enforces and strengthens our implementations for threats 5 and 7. This feature works by adding a timestamp to the token and checking if the token has expired. If it has, the user will be disconnected and will have to re-authenticate. This will prevent any stolen tokens from being used for a long period of time.




# References

https://auth0.com/docs/secure/tokens/token-best-practices
https://www.cs.cornell.edu/courses/cs513/2007fa/NL11Lamport.html
https://www.techtarget.com/searchsecurity/definition/Hash-based-Message-Authentication-Code-HMAC
