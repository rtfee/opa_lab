package terraform

import rego.v1

# Deny if any modules use non-account registry sources
deny[msg] if {
    count(invalid_modules) > 0
    msg := sprintf("Policy violation: %d module(s) found using non-account registry sources. All modules must use scalrdemov2.scalr.io as the source.", [count(invalid_modules)])
}

# Find all modules with invalid sources
invalid_modules contains module if {
    some module_name, module_config in input.tfplan.configuration.root_module.module_calls
    not startswith(module_config.source, "scalrdemov2.scalr.io")
    module := {
        "name": module_name,
        "source": module_config.source,
        "address": sprintf("module.%s", [module_name])
    }
}

# Detailed violation information
violation_details contains detail if {
    some module in invalid_modules
    detail := {
        "module": module.address,
        "source": module.source,
        "message": "Module source must start with 'scalrdemov2.scalr.io'"
    }
}
