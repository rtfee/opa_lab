package terraform

import input.tfplan as tfplan

# Default deny - all module sources must be validated
default allow := false

# Allow if all module sources use the account registry
allow if {
    count(invalid_modules) == 0
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

# Violation message for non-compliant modules
violation[msg] if {
    count(invalid_modules) > 0
    msg := sprintf("Policy violation: %d module(s) found using non-account registry sources. All modules must use scalrdemov2.scalr.io as the source.", [count(invalid_modules)])
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

# Advisory information for compliant configurations
advisory[msg] if {
    count(invalid_modules) == 0
    total_modules := count(input.tfplan.configuration.root_module.module_calls)
    total_modules > 0
    msg := sprintf("All %d module(s) correctly use scalrdemov2.scalr.io as the source.", [total_modules])
}
