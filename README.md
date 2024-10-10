# Updated Kubernetes postgres-controller

  <img src="https://raw.githubusercontent.com/max-rocket-internet/postgres-controller/master/img/k8s-logo.png" width="100"> + <img src="https://raw.githubusercontent.com/max-rocket-internet/postgres-controller/master/img/postgres-logo.png" width="100">

Forked from [max-rocket-internet/postgres-controller](https://github.com/max-rocket-internet/postgres-controller) this attempts to add specific functionality around it that I wanted/needed. In particular, being able to store passwords in secrets as much as possible. Also refactored a lot of the code so that it feels easier to follow and attempted to comment most of it.

It's worth noting this is a bit of a learning-in-progress piece and this has only been tested manually so use at OWN RISK.

Because of the changes made it makes sense to provide an example separate from the original:

```yaml
apiVersion: postgresql.org/v1
kind: PostgresDatabase
metadata:
  name: app1
spec:
  dbName: 
    value: db1
  dbRoleName: 
    envFrom:
      configMapKeyRef:
        name: db-config
        namespace: postgres-controller
        key: username
  dbRolePassword: 
    envFrom:
      secretKeyRef:
        - name: db-password
          namespace: postgres-controller
```
