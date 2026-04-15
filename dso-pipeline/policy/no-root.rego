package main

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot
    msg := sprintf("Le conteneur '%s' doit avoir runAsNonRoot: true", [container.name])
}

deny[msg] {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation
    msg := sprintf("Le conteneur '%s' ne doit pas autoriser l'escalade de privilèges", [container.name])
}
