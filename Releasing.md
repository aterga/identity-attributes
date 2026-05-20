# Releasing

The `mops-publish.yml` workflow publishes a new version to [mops.one](https://mops.one) whenever a tag matching `v*.*.*` is pushed. The release process is:

1. Bump `version` in `mops.toml`.
2. Update the version in the install snippet in `README.md`.
3. In `Changelog.md`, rename the `## Next` section to `## X.Y.Z` and add a fresh empty `## Next` at the top.
4. Open a PR with those changes; merge once green.
5. From `main`, tag the merge commit:

   ```
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

6. `mops-publish.yml` picks up the tag and publishes to mops.one. Check the workflow run to confirm success.

The workflow requires the repository secret `MOPS_IDENTITY_PEM` — a Mops publisher identity exported via `mops user export`. Set it under **Settings → Secrets and variables → Actions**.
