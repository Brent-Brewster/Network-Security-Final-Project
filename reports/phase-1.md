# Team Information
Alex Glebavicius, alg265@pitt.edu, AlexGlebo
Brent Brewster, bhb19@pitt.edu, Brent-Brewster
Brett Craskey, btc41@pitt.edu, Craskeyb

# Section 1: Selected Application

For our messaging service, we aim to develop an encrypted messaging platform that prioritizes security and user authentication. Users will be required to sign in and have their accounts verified by an authentication server, which will occur once per session. Once a user is signed in and authenticated, they will have the ability to create messaging groups with one or more other users. Messages will be stored on separate file/message servers and accessed by authorized users.

Similar to the file sharing model, our authentication server will manage all system users and assign permissions accordingly. Users will only be able to see messages in groups they are included in. Additionally, users should have the ability to create new groups and make edits to existing groups, such as removing users or adding new ones. Furthermore, users will have the option to edit previously sent messages, which will override the original message and display the edited version to all recipients.

[figure1](figure1.jpg)

# Section 2: Security Properties

- **Property 1**:

    - **Name**: Audit Logging

    - **Definition**: Audit logging is the process of documenting activity within the system to log records of events to find when and who was responsible for an action.

    - **Description**: Audit Logging is a helpful security feature that can monitor activity to detect security flaws and incidents. If user A performed an action to crash the server, we can view the logs before the crash and discover what was done in this attempt, when it happened, and what user was responsible for it. This is important because these logs can provide helpful trails and information to detect and fix any flaws or misuse of the application that can put the users and data at risk.

    - **Assumptions**: This assumes we have implemented a functional logging mechanism and securely store these logs. We also assume we have the ability for authorized and secure administrators to be able to view and analyze these logs for security purposes only.

- **Property 2**:

    - **Name**: Secure File Transfer

    - **Definition**: A data-sharing method that uses secure protocols and encryption to safeguard data in transit. 

    - **Description**: Secure file transfer will safeguard the confidentiality and integrity of resources shared between users by encrypting during transporting and securely storing it. If user A shares a picture with user B, a middleman or nonauthorized user should not be able to intercept the data in transit. This is important because no user should worry about the confidentiality and integrity of their resources when they send messages or resources to other users.

    - **Assumptions**: This assumes we have implemented a protocol similar to SFTP or various encryption methods to protect the resources while transmitting.


- **Property 3**:

    - **Name**: User Privacy

    - **Definition**: Protects the user's personal information and prevents unauthorized collection or use. 

    - **Description**: Using privacy regulations ensures that personal data will be securely managed and stored and only used for authorized purposes such as auditing. Furthermore, ensure data is not being shared without user consent. This is important because no user should have their personal data being sold without their knowledge and should have trust in the application that they are protecting it from leaks and malicious sources. For example, if user A shares an emotional circumstance with user B, a malicious user such as user C should not be able to easily collect this information and use it as blackmail or sell the data for profit. Similarly, the administration should not sell or use data for profit unless user consent is given.

    - **Assumptions**: This assumes the implementation of data protection measures such as encryption, and compliance with regulations for relevant user privacy. 


- **Property 4**:

    - **Name**:  Message Integrity 

    - **Definition**: Integrity ensures that resources will be unaltered between the transmission of data

    - **Description**: Message integrity will allow for the trust of content shared between users preventing unauthorized manipulation or altering while being sent. For example, user A should not worry about the origin integrity of user B’s message and if it was them who really sent the message. 

    - **Assumptions**: This assumes we will use cryptographic techniques such as hashing to verify the integrity of messages being sent. 

- **Property 5**:

    - **Name**: Denial of Service (DDOS) Protection

    - **Definition**: DDOS protection allows for protection from malicious attacks attempting to disrupt availability or functionality 

    - **Description**: Protection mechanisms can help reduce stress and mitigate the effects of these attacks that can disrupt services which helps ensure a higher rate of availability for the application.

    - **Assumptions**: This assumes the implementation of traffic filtering such as using segments of the network to distribute connections to prevent overloading a singular connection or port. It further assumes we implemented resource monitoring to help detect and analyze network traffic to reduce or stop these attacks. 


- **Property 6**:

    - **Name**: Prevention of internal sabotage 

    - **Definition**: Any user in the application should be designed following the principles of least privilege and separation of privilege 

    - **Description**: To prevent internal sabotage and ensure the availability of the application, any user should operate using the least amount of privileges necessary to still properly operate. Furthermore, administrators with access to confidential information require two keys to open and access. This is important to help prevent insiders from destroying the application and users operating with too much power which leads to vulnerabilities.

    - **Assumptions**: The system uses mechanisms to assign users with appropriate privileges based on their roles or responsibilities. Any administrative action requires multiple authentications. The system uses proper authentication and authorization mechanisms to enforce the principles. 


- **Property 7**:

    - **Name**:  Prevent unauthorized access
    - **Definition**: No user should be able to read any other users messages

    - **Description**: Every message sent needs to be protected from unauthorized access. Meaning that no user that does not belong to the group the message was sent to should be able in any way to read that message 

    - **Assumptions**: The Authentication server needs to be trusted and well maintained in order to trust its ability to correctly report a user's abilities to access, read, and send messages to groups that only that user belongs to or has created.  


- **Property 8**:

    - **Name**: Prevent hardware attacks with messages and data stored on the file servers

    - **Definition**: No individual with access to the servers hardware E.G., hard drive should be able to read any plain text messages stored on the server.

    - **Description**: In the event that any individual external or internal gains access to the server hardware itself they should not be able to simply look through the hard disk and read any messages stored on the hard disk. This is important to ensure the confidentiality of messages on our service. A user needs to be confident that no one can see the messages they are sending or receiving. 

    - **Assumptions**: This assumes that we would be able to use an encryption algorithm to encrypt the messages that are stored on disk itself as well as messages in transit. It also assumes that we’d be able to keep this key somewhere that a potential attacker could not access. 


- **Property 9**:

    - **Name**: Authentication 
    - **Definition**: The process of verifying the identity/integrity of the user, ensuring they are who they claim to be.

    - **Description**: Authentication is essential to prevent and reduce unauthorized users accessing accounts they should not be on. This will help enforce the integrity of interactions between users by not having to worry about impersonators or hacked accounts. For example, if the CEO messages user A, they should not worry that the CEO was hacked and that it is an authentic claim of the CEO interacting with user A

    - **Assumptions**: We assume there is a secure system to create and register as a user. We also assume there is a security mechanism in place to verify and check user credentials when they are entered, this can be supported by a mechanism such as ‘Open Mediation’


- **Property 10**:

    - **Name**: Secure Group Actions

    - **Definition**: Any actions that can be taken within the context of a group - adding/removing users, sending messages to the group, etc. - will be secure and only permitted to members of the group.

    - **Description**: In order to maintain integrity within groups, it is imperative that the groups operate within the principle of fail-safe default: they need to be permission-based for any related actions that could alter the group. Users who are not members of a group should not be able to access the messages in the group, add themselves or other people, or remove anyone from the group.

    - **Assumptions**: This assumes that we have implemented a security mechanism within groups that restricts permission to any group-based action if the user is not already a member of the group.


- **Property 11**:

    - **Name**: Public Documentation & Codebase

    - **Definition**: All relevant documentation will be publicly visible following the principle of open design in order to promote open review and timely discovery/reporting of bugs within the system.

    - **Description**: Given that our application requires many levels of cryptographic protection and security measures, it is important that our design is public to encourage open review so that any security issues are likely to be discovered in a timely manner. The discovery and patching of bugs is very important in the case of something like a messaging service, because there could be a large amount of confidential user data being shared or stored on the servers.

    - **Assumptions**: This assumes that we publish our application publicly somewhere for open review, and that users will make use of the documentation & report any bugs either to us or to the public.


- **Property 12**:

    - **Name**: Message Data Confidentiality

    - **Definition**:  Protects and ensures the user message existence remain unknown to outside people looking at the server memory/disk

    - **Description**: If an attacker were to gain access to the internal file server we need to ensure that that attacker would be unable to see the existence of a person's messages. This could be both an encryption of the user messages and data as well as restricting access to directories that store the users data and only gaining access to those directories with a key provided by the Authentications server.

    - **Assumptions**: The attacker would not be able to retrieve or guess the users key, and the Authentication server needs to be trusted. 


- **Property 13**:

    - **Name**:  User Confidentiality

    - **Definition**: Attempt to ensure the Users of the messaging service remain secret to outside attackers

    - **Description**: Maintaining user confidentiality should ensure that people looking into the directories or storage devices of the Authentication server or the file server should not be able to see who is sending or receiving messages. In order to do this Much like protecting message confidentiality, we should not only encrypt the user data and information, but also restrict access to folders or directories which store the information. In order to hide the users login information they could be sent to the authentication server using a secure hash function and looking up their information from that hash generated ensuring that the users name is not accessible even on the Authentication server.

    - **Assumptions**: There exists some secure hash function that handles collisions in such a way that a user would be able to type in their specific login information and would always be given the same hash in order for the Authentication server to use that instead of their name and password.


- **Property 14**:

    - **Name**:  User Spoofing

    - **Definition**: Prevent an attacker's ability to spoof a user and send a message that did not originate from that user

    - **Description**: Using the Authentication server a user should be able to use their specific information to sign into an account granting them access to their data. This could be done by the Authentication server providing the user with a secure token that the file servers would verify before allowing a message to be placed into a user message group. The session token would also need to be sent using some sort of encryption to ensure that not attacker could receive it while in transmission. 

    - **Assumptions**: The attacker would not have the users personal sign in information and the Authentication server would need to be trusted not to share a users session token with anyone else. 


- **Property 15**:

    - **Name**: Intuitive User Interface

    - **Definition**: The interface for users is simple to use and avoids confusing or convoluted processes for both authentication & regular use.

    - **Description**: Ensuring concise and intuitive operation of the application & security measures will help to ensure that users are able to correctly perform any desired/required actions with minimal risk of mistakes, in line with the principle of psychological acceptability. If the routine security measures are difficult to use, it is more likely that there could be instances of incorrect use which could lead to attacks or data leaks. The same risks apply if the application is hard to use; for example if a user accidentally adds/removes someone from a group or shares confidential information to the wrong group. This can be avoided by making sure any interfaces/commands are visually clean and intuitive for users.

    - **Assumptions**: The users of the application have a general level of computer literacy & have used other messaging services before, and we have designed our commands/interfaces to be intuitive for that demographic.


# Section 3: Threat Models

- **Threat Model 1: Enterprise Messaging System**

    - **Description and Environment**: This would be a platform used by a company for employers to communicate internally within the company's network/infrastructure by sharing messages, or pictures between co-workers, groups, etc. For example, similar to how a company would use Microsoft Teams to communicate and chat.

    - **Trust Assumptions**: The users of this platform use devices that are secure. E.g. no malware or backdoors that attackers could use to snoop with. Users trust the integrity of the other users they message or interact with. Users are trusted to protect the confidentiality of their logins and not share them with outside, unauthorized users. The server is capable of securely storing data that entails user credentials, messages, etc. The IT department creates accounts for current and new employees to prevent impersonations.

    - **Relevant Security Properties**:
        - Message Integrity: Any messages sent between users will be unaltered while transmitted, protecting the origin integrity. 
        - Authentication: Any user must enter valid credentials to access their respective account.
        - User Authentication: Users must follow protocols to login and access their accounts such as multi-factor authentication or even biometrics to reduce the likelihood of attackers hacking accounts.
        - User Privacy: Any personal data or information from users will be protected and not shared without proper consent.
        - Prevention of internal sabotage: No user should have the permissions or powers to sabotage other users or take down the system supported by mechanisms such as the separation of privilege and least privilege. 
        - Secure Data Storage: Any data pertaining to the users such as messages, or even company data are securely stored to prevent data breaches. 

- **Threat Model 2: Personal Messaging System**
    
    - **Description and Environment**: This would be a platform used by any individuals to communicate externally with groups of friends, family, colleagues, etc. An example of this style of messaging system would be something like Discord, where people can join communities to message people & share files for a variety of purposes.

    - **Trust Assumptions**: The users’ devices may not be secure, and should not be trusted to be safe from malware, internal attacks, or snooping. Users trust the integrity of the other users they message or interact with. Users are trusted to protect the confidentiality of their logins and not share them with outside, unauthorized users. The server is capable of securely storing data that entails user credentials, messages, etc. Users create their own accounts for personal use, so it is up to the authentication server & the users to identify any impersonations in the application. The users learn to use the application on their own, and have varying degrees of technical literacy.

    - **Relevant Security Properties**:
        - Message Integrity: Any messages sent between users will be unaltered while transmitted, protecting the origin integrity. 
        - Authentication: Users must follow protocols to login and access their accounts such as multi-factor authentication or even biometrics to reduce the likelihood of attackers hacking accounts.
        - Intuitive User Interface: The interface for users is simple to use and avoids confusing or convoluted processes for both authentication & regular use.
        - User Privacy: Any personal data or information from users will be protected and not shared without proper consent.
        - Prevention of internal sabotage: No user should have the permissions or powers to sabotage other users or take down the system supported by mechanisms such as the separation of privilege and least privilege. 
        - Secure Data Storage: Any data pertaining to the users such as messages, or even company data are securely stored to prevent data breaches. 
        - Public Documentation & Codebase: All relevant documentation will be publicly visible following the principle of open design in order to promote open review and timely discovery/reporting of bugs within the system.


# Section 4: References

- https://www.vmware.com/topics/glossary/content/application-security.html

- Lecture Notes

- https://irp.fas.org/nsa/rainbow/tg026.htm

