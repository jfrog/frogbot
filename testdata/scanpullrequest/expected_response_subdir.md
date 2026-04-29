

[comment]: <> (FrogbotReviewComment)

<div align='center'>

[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>



## 📗 Scan Summary
- Frogbot scanned for vulnerabilities and found 1 issues

| Scan Category                | Status                  | Security Issues                  |
| --------------------- | :-----------------------------------: | ----------------------------------- |
| **Software Composition Analysis** | ✅ Done | <details><summary><b>1 Issues Found</b></summary><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallCritical.svg" alt=""/> 1 Critical<br></details> |
| **Contextual Analysis** | ✅ Done | - |
| **Static Application Security Testing (SAST)** | ✅ Done | Not Found |
| **Secrets** | ✅ Done | - |
| **Infrastructure as Code (IaC)** | ✅ Done | Not Found |

### 📦 Vulnerable Dependencies

| Severity                | ID                  | Contextual Analysis                  | Dependency Path                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | ----------------------------------- |
| ![critical (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | CVE-2021-44906 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimist:1.2.5<br></details> |

### 🔖 Details



### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 9.8 |
| **Dependency Path:** | <details><summary><b>minimist: 1.2.5 (Direct)</b></summary>Fix Version: 1.2.6<br></details> |

Minimist prior to 1.2.6 and 0.2.4 is vulnerable to Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95).

---
<div align='center'>

[🐸 JFrog Frogbot](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>
