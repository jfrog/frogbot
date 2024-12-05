
## 🚥 Policy Violations

### 🚨 Security Violations

<div align='center'>

| Severity/Risk                | ID                | Contextual Analysis                  | Direct Dependencies                  | Impacted Dependency                  | Watch Name                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/notApplicableCritical.png)<br>Critical | CVE-1111-11111 | Not Applicable | dep1:1.0.0<br>dep2:2.0.0 | impacted 3.0.0 | sca-watch |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | XRAY-122345 | Undetermined | github.com/nats-io/nats-streaming-server:v0.21.0 | github.com/nats-io/nats-streaming-server v0.21.0 | [0.24.1] |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | CVE-2022-26652<br>CVE-2023-4321 | Applicable | component-D:v0.21.0 | component-D v0.21.0 | [0.24.3] |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableLowSeverity.png)<br>     Low | - | Undetermined | github.com/mholt/archiver/v3:v3.5.1 | github.com/mholt/archiver/v3 v3.5.1 | - |

</div>


### 🔖 Details

<details> 
<summary> <b>[ CVE-1111-11111 ] impacted 3.0.0 (sca-watch)</b> </summary>

### Violation Details

|  |  |
| :--- | :--- |
__Policies:__| xsc-policy-1
__Watch Name:__| xsc-watch
__JFrog Research Severity:__| ![](https://raw.githubusercontent.com/jfrog/jfrog-ide-webview/main/src/assets/icons/severity/critical.svg) Critical
__Contextual Analysis:__| Applicable
__Direct Dependencies:__| flask:1.1.2
__Impacted Dependency:__| werkzeug:1.0.1
__Fix Versions:__| 4.0.0, 5.0.0
__CVSS V3:__| 9.8

some-summary

### 🔬 JFrog Research Details

**Description:**
Summary XRAY-122345

**Remediation:**
some remediation

</details>

<details>
<summary> <b>[ XRAY-122345 ] github.com/nats-io/nats-streaming-server v0.21.0</b> </summary>
<br>


**Description:**
Summary XRAY-122345

**Remediation:**
some remediation

</details>

<details>
<summary> <b>[ CVE-2022-26652, CVE-2023-4321 ] component-D v0.21.0</b> </summary>
<br>


**Remediation:**
some remediation

</details>

<details>
<summary> <b> github.com/mholt/archiver/v3 v3.5.1</b> </summary>
<br>


**Description:**
Summary

</details>
