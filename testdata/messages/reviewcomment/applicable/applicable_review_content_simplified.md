

---
## 📦🔍 Contextual Analysis CVE

---
| Severity                | Impacted Dependency                  | Finding                  | CVE                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| Critical | werkzeug:1.0.1 | The vulnerable function flask.Flask.run is called | CVE-2022-29361 |

---
### Description

---
The scanner checks whether the vulnerable `Development Server` of the `werkzeug` library is used by looking for calls to `werkzeug.serving.run_simple()`.

---
### CVE details

---
cveDetails

---
### Remediation

---
some remediation