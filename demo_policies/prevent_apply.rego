# Allprod  runs must be approved
package terraform
import input.tfrun as tfrun

# Deny if auto-apply is enabled
deny["auto-apply is not allowed"] if {
  tfrun.workspace.auto_apply == true
}
