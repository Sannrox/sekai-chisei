# Keep Health Fallback Before Egress

## What happened
Provider health could only reject at contact time, where changing providers would bypass or duplicate earlier governance checks.

## Root cause
Health was tracked below policy resolution even though cross-provider fallback changes capability and data-governance boundaries.

## Rule
Select fallbacks from policy-authorized alternatives before egress, then recheck capability, governance, budget, and egress constraints for the selected route.
