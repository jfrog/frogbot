

---
## 🛠️ Infrastructure as Code Vulnerability

---
| Severity                | Finding                  |
| :---------------------: | :-----------------------------------: |
| Medium | Missing auto upgrade was detected |

---
### Full description

---
Resource `google_container_node_pool` should have `management.auto_upgrade=true`

Vulnerable example - 
```
resource "google_container_node_pool" "vulnerable_example" {
    management {
     auto_upgrade = false
   }
}
```
