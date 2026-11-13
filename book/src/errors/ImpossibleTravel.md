# ImpossibleTravel

## Summary
There is an inconsistency between the client address used to request the access token,
and the current client address used to call the service. Please re-authenticate with
the current address to resolve the issue.

## Examples
- the `ip_address` claim of the access token differs from the client address of the
  current request (only checked when `pep_no_travel on;` is set)
