# Test fixtures

`policies/` holds the three policies of
[plugin-http-collector-policies](https://github.com/compliance-framework/plugin-http-collector-policies),
copied unchanged from commit `3f4811593af2df92021d9baccb4b43181e6f2fe2` (the Rego v1 conversion in
plugin-http-collector-policies#2). Their `_test.rego` files are left out: the policy manager skips them.

The plugin tests evaluate these files as the policy bundle. When the policies change, copy the new versions
here and update the commit above.
