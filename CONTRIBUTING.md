# Contributing

Keep changes bounded to the public Velociraptor skills and shared runtime.
Update documentation and tests with behavior changes. Examples must use
sanitized hostnames, addresses, identities, and case names.

Run:

```sh
./utils/validate-public-export.sh
```

Repository synchronization is direction-explicit. If the same managed file
changed in both repositories, resolve it manually and establish identical
content before updating the synchronization baseline.
