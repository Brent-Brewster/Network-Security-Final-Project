## Phase 4 Extra Credit

# Feature: Token Expiration

- For the phase 4 extra credit, we added a feature where we now have tokens that expire after 'x' amount of time. This feature enforces and strengthens our implementations for threats 5 and 7. This feature works by adding a timestamp to the token and checking if the token has expired. If it has, the user will be disconnected and will have to re-authenticate. This will prevent any stolen tokens from being used for a long period of time.

- As we continue to test and improve our system we will currently experiment with an expiration time of a 5 minutes, but this can be changed to any amount of time and when the application is deployed it will be set to a more reasonable time such as one hour. 

- This is beneficial to have as a feature because if there is any flaw in our other security features, the expiration will help refresh tokens and require users to re-authenticate. For example, if a user token was stolen, it will only be valid for a short period of time and will not be able to be used for a long period of time.

- In 'Token.Java' we created a new method called isTokenValid() which is a boolean that will check the current time against the allowed time for a token since issuance. This will be called before any action such as createGroup, addUser, etc., and check if the current client's token is still valid. If it is not they will be disconnected and asked to reauthenticate. 


### References

https://auth0.com/docs/secure/tokens/token-best-practices
