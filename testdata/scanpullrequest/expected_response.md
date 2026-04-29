

[comment]: <> (FrogbotReviewComment)

<div align='center'>

[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>



## 📗 Scan Summary
- Frogbot scanned for vulnerabilities and found 3 issues

| Scan Category                | Status                  | Security Issues                  |
| --------------------- | :-----------------------------------: | ----------------------------------- |
| **Software Composition Analysis** | ✅ Done | <details><summary><b>3 Issues Found</b></summary><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallCritical.svg" alt=""/> 2 Critical<br><img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallHigh.svg" alt=""/> 1 High<br></details> |
| **Contextual Analysis** | ✅ Done | - |
| **Static Application Security Testing (SAST)** | ✅ Done | Not Found |
| **Secrets** | ✅ Done | - |
| **Infrastructure as Code (IaC)** | ✅ Done | Not Found |

### 📦 Vulnerable Dependencies

| Severity                | ID                  | Contextual Analysis                  | Dependency Path                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | ----------------------------------- |
| ![critical](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical | CVE-2015-8857 | Not Covered | <details><summary><b>1 Direct</b></summary>uglify-js:2.2.5<br></details> |
| ![critical (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | CVE-2021-44906 | Not Applicable | <details><summary><b>1 Direct</b></summary>minimist:1.2.5<br></details> |
| ![high (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableHigh.png)<br>    High | CVE-2015-8858 | Not Applicable | <details><summary><b>1 Direct</b></summary>uglify-js:2.2.5<br></details> |

### 🔖 Details


<details><summary><b>[ CVE-2015-8857 ] uglify-js 2.2.5</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Covered |
| **CVSS V3:** | 9.8 |
| **Dependency Path:** | <details><summary><b>uglify-js: 2.2.5 (Direct)</b></summary>Fix Version: 3.4.10<br></details> |

The uglify-js package before 2.4.24 for Node.js does not properly account for non-boolean values when rewriting boolean expressions, which might allow attackers to bypass security mechanisms or possibly have unspecified other impact by leveraging improperly rewritten Javascript.<br></details>

<details><summary><b>[ CVE-2021-44906 ] minimist 1.2.5</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 9.8 |
| **Dependency Path:** | <details><summary><b>minimist: 1.2.5 (Direct)</b></summary>Fix Version: 1.2.6<br></details> |

Minimist prior to 1.2.6 and 0.2.4 is vulnerable to Prototype Pollution via file `index.js`, function `setKey()` (lines 69-95).<br></details>

<details><summary><b>[ CVE-2015-8858 ] uglify-js 2.2.5</b></summary>

### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Contextual Analysis:** | Not Applicable |
| **CVSS V3:** | 7.5 |
| **Dependency Path:** | <details><summary><b>uglify-js: 2.2.5 (Direct)</b></summary>Fix Version: 3.4.10<br></details> |

The uglify-js package before 2.6.0 for Node.js allows attackers to cause a denial of service (CPU consumption) via crafted input in a parse call, aka a "regular expression denial of service (ReDoS)."<br></details>

---
<div align='center'>

[🐸 JFrog Frogbot](https://jfrog.com/help/r/jfrog-security-user-guide/shift-left-on-security/frogbot)

</div>
