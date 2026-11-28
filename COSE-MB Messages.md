# COSE for Micro-Blogging Messages

Document version ID: 20261128

Then encoding process is as follows:

1. Payload (optional, based on the message profile): See [Encrypted Message Payload](Encrypted%20Message%20Payload.md)
2. Message Profile
3. Place the message profile in the `COSE_MB` COSE object
4. Encode that object. See [Encoded Message to Text](Encoded%20Message%20to%20Text.md)

## `COSE_MB` Object

```cddl
COSE_MB = {
    &(p_object: 0) => bstr,
    &(p_id: 1) => int,
}
```

* `p_object`: The COSE object
* `p_id`: The ID of the profile

# Profiles:

- ID 1: [Public Key Message Profile](Public%20Key%20Message%20Profile.md)
- ID 2: [Single-Recipient Encrypted Message Profile](Singe-Recipient%20Encrypted%20Message%20Profile.md)
