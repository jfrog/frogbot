
## 🚥 Policy Violations


### ⚖️ License Violations

<div align='center'>

| Severity                | License                  | Direct Dependencies                  | Impacted Dependency                  | Watch Name                  |
| :---------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: | :-----------------------------------: |
| ![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | License1 | Comp1:1.0 | Dep1:2.0 | watch |
| ![high](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableHighSeverity.png)<br>    High | License2 | root:1.0.0<br>minimatch:1.2.3 | Dep2:3.0 | watch2 |

</div>


### 🔖 Details


<details><summary><b>[ License1 ] Dep1 2.0 (watch)</b></summary>

### Violation Details
| --------------------- | :-----------------------------------: |
| **Policies:** | policy1, policy2 |
| **Watch Name:** | watch |
| **Direct Dependencies:** | Comp1:1.0 |
| **Impacted Dependency:** | Dep1:2.0 |
| **Full Name:** | License1 full name |

<br></details>

<details><summary><b>[ License2 ] Dep2 3.0 (watch2)</b></summary>

### Violation Details
| --------------------- | :-----------------------------------: |
| **Policies:** | policy3 |
| **Watch Name:** | watch2 |
| **Direct Dependencies:** | root:1.0.0, minimatch:1.2.3 |
| **Impacted Dependency:** | Dep2:3.0 |
| **Full Name:** | - |

<br></details>