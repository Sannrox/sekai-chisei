# Keep Registry Authority Off Hot Request Paths

## What happened
A registry migration preserved canonical namespaced routing but broke legacy bare aliases, selected wire-incompatible automatic defaults, and performed blocking filesystem refreshes inside async requests.

## Root cause
Registry authority was applied at low-level resolution points without preserving ingress context or separating durable refresh from cached request-time reads.

## Rule
Refresh durable registry state outside async hot paths, then resolve from a versioned snapshot while preserving client-wire alias and default compatibility.
