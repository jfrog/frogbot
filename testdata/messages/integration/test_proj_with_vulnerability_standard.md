

[comment]: <> (FrogbotReviewComment)

<div align='center'>

[![🚨 Frogbot scanned this pull request and found the below:](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/vulnerabilitiesBannerPR.png)](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot)

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

<div align='center'>

| Severity                | ID                  | Contextual Analysis                  | Direct Dependencies                  | Impacted Dependency                  | Fixed Versions                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![critical (not applicable)](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | CVE-2021-44906 | Not Applicable | minimist:1.2.5 | minimist 1.2.5 | [0.2.4]<br>[1.2.6] |

</div>


### 🔖 Details



### Vulnerability Details
|                 |                   |
| --------------------- | :-----------------------------------: |
| **Jfrog Research Severity:** | <img src="https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/smallHigh.svg" alt=""/> High |
| **Contextual Analysis:** | Not Applicable |
| **Direct Dependencies:** | minimist:1.2.5 |
| **Impacted Dependency:** | minimist:1.2.5 |
| **Fixed Versions:** | [0.2.4], [1.2.6] |
| **CVSS V3:** | 9.8 |

Insufficient input validation in Minimist npm package leads to prototype pollution of constructor functions when parsing arbitrary arguments.

### 🔬 JFrog Research Details

**Description:**
[Minimist](https://github.com/substack/minimist) is a simple and very popular argument parser. It is used by more than 14 million by Mar 2022. This package developers stopped developing it since April 2020 and its community released a [newer version](https://github.com/meszaros-lajos-gyorgy/minimist-lite) supported by the community.


An incomplete fix for [CVE-2020-7598](https://nvd.nist.gov/vuln/detail/CVE-2020-7598) partially blocked prototype pollution attacks. Researchers discovered that it does not check for constructor functions which means they can be overridden. This behavior can be triggered easily when using it insecurely (which is the common usage). For example:
```
var argv = parse(['--_.concat.constructor.prototype.y', '123']);
t.equal((function(){}).foo, undefined);
t.equal(argv.y, undefined);
```
In this example, `prototype.y`  is assigned with `123` which will be derived to every newly created object. 

This vulnerability can be triggered when the attacker-controlled input is parsed using Minimist without any validation. As always with prototype pollution, the impact depends on the code that follows the attack, but denial of service is almost always guaranteed.

**Remediation:**
##### Development mitigations

Add the `Object.freeze(Object.prototype);` directive once at the beginning of your main JS source code file (ex. `index.js`), preferably after all your `require` directives. This will prevent any changes to the prototype object, thus completely negating prototype pollution attacks.



---
<div align='center'>

[🐸 JFrog Frogbot](https://docs.jfrog-applications.jfrog.io/jfrog-applications/frogbot)

</div>
