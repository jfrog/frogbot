
## 🗝️ Secret Detected
<div align='center'>

| Severity                | Finding                  | Status                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | Secret keys were found | Active |

</div>

<details>
<summary> <b>Full description</b> </summary>
<br>

Storing hardcoded secrets in your source code or binary artifact could lead to several risks.

If the secret is associated with a wide scope of privileges, attackers could extract it from the source code or binary artifact and use it maliciously to attack many targets. For example, if the hardcoded password gives high-privilege access to an AWS account, the attackers may be able to query/modify company-wide sensitive data without per-user authentication.

## Best practices

Use safe storage when storing high-privilege secrets such as passwords and tokens, for example -

* ### Environment Variables

Environment variables are set outside of the application code, and can be dynamically passed to the application only when needed, for example -
`SECRET_VAR=MySecret ./my_application`
This way, `MySecret` does not have to be hardcoded into `my_application`.

Note that if your entire binary artifact is published (ex. a Docker container published to Docker Hub), the value for the environment variable must not be stored in the artifact itself (ex. inside the `Dockerfile` or one of the container's files) but rather must be passed dynamically, for example in the `docker run` call as an argument.

* ### Secret management services

External vendors offer cloud-based secret management services, that provide proper access control to each secret. The given access to each secret can be dynamically modified or even revoked. Some examples include -

* [Hashicorp Vault](https://www.vaultproject.io)
* [AWS KMS](https://aws.amazon.com/kms) (Key Management Service)
* [Google Cloud KMS](https://cloud.google.com/security-key-management)

## Least-privilege principle

Storing a secret in a hardcoded manner can be made safer, by making sure the secret grants the least amount of privilege as needed by the application.
For example - if the application needs to read a specific table from a specific database, and the secret grants access to perform this operation **only** (meaning - no access to other tables, no write access at all) then the damage from any secret leaks is mitigated.
That being said, it is still not recommended to store secrets in a hardcoded manner, since this type of storage does not offer any way to revoke or moderate the usage of the secret.


</details>
