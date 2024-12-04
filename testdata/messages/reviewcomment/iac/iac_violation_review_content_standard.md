
## 🛠️ Infrastructure as Code Violation
<div align='center'>

| Severity                | ID                  |  Finding                  |
| :---------------------: | :-----------------------------------: |:-----------------------------------: |
| ![](https://raw.githubusercontent.com/jfrog/frogbot/master/resources/v2/applicableMediumSeverity.png)<br>  Medium | VIOLATION_ID  | Missing auto upgrade was detected |

</div>

<details>
<summary> <b>Full description</b> </summary>

#### Violation Details
|  |  |
| :--- | :--- |
__Policies:__| xsc-policy-1
__Watch Name:__| xsc-watch
__CWE:__| CWE-89


Resource `google_container_node_pool` should have `management.auto_upgrade=true`

Vulnerable example - 
```
resource "google_container_node_pool" "vulnerable_example" {
    management {
     auto_upgrade = false
   }
}
```


</details>
