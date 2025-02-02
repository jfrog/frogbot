
## 📦🔍 Contextual Analysis CVE
<div align='center'>

| Severity                | ID                  | Impacted Dependency                  | Finding                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![critical](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableCriticalSeverity.png)<br>Critical | CVE-2022-29361 | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called |

</div>

<details><summary><b>Description</b></summary>
The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.
<br></details>
<details><summary><b>CVE details</b></summary>
cveDetails
<br></details>
<details><summary><b>Remediation</b></summary>

some remediation

<br></details>