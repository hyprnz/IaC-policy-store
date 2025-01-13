# iac-policy-opa-store

This repo serves as a centralised OPA policy bundle store. Policies can be developed and tested in this repo and then be pulled into the specific service and tested. Policy tests can use either [opa](https://www.openpolicyagent.org/docs/latest/#overview) or [Conftest](https://www.conftest.dev/).

## Getting started

All polices should be stored in a folder and should contain a README, tests, any data files required. At this stage we're not creating bundles, but in the future this could be implemented with a OCI registry.
