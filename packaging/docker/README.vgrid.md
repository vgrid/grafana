# Publish the vGRID Grafana image

The **Publish vGRID Grafana to GHCR** workflow builds the fork's frontend and backend inside Docker and publishes an Alpine-based OSS image for `linux/amd64`.
It runs only when manually dispatched. It doesn't publish on pushes or pull requests, and it doesn't update `latest`.

## Set up GitHub Actions

1. Enable GitHub Actions in `vgrid/grafana` if workflows are disabled for the fork.
2. Make `.github/workflows/vgrid-publish-ghcr.yml` available on the repository's default branch. GitHub requires this before you can manually dispatch the workflow.
3. Ensure repository and organization Actions policies allow the workflow's actions and its `packages: write` permission.

The workflow uses the built-in `GITHUB_TOKEN`. You don't need a Docker Hub account, a personal access token, or additional repository secrets.
It uses a standard GitHub-hosted Ubuntu x64 runner, not Grafana's internal runners.

## Publish an image

1. Commit and push the source you want to publish after review.
2. Open **Actions → Publish vGRID Grafana to GHCR → Run workflow**.
3. Select the branch or tag containing that source.
4. Enter a version such as `13.3.0-vgrid.1` and start the workflow.

Versions must have the form `<MAJOR>.<MINOR>.<PATCH>-vgrid.<REVISION>`.
Use a new revision for each release. Reusing a version replaces that image tag.
The workflow builds the selected commit, verifies the image architecture, and starts an isolated container to check `/api/health` before logging in and pushing.
This startup check doesn't verify Entra ID login or team mapping. Test those separately against a staging database before production deployment.

For `vgrid/grafana`, the resulting image is:

```text
ghcr.io/vgrid/grafana:13.3.0-vgrid.1
```

The workflow derives the image name from the repository name and adds source, commit, license, and version labels.
The source label links the container package to the repository.
The Actions run summary includes the published image and source commit.

## Pull and deploy

New container packages default to private. To allow anonymous pulls, open the package's settings and change its visibility to public if your organization permits it.
For private packages, authenticate deployment hosts to `ghcr.io` with a credential that has `read:packages` access to this package.

Pull a published version with:

```sh
docker pull ghcr.io/vgrid/grafana:13.3.0-vgrid.1
```

Keep OAuth secrets, database credentials, and environment-specific configuration outside the image. Supply them at runtime through your existing deployment configuration.
Retain the AGPL license notices and provide the corresponding modified source when distributing the image.
Back up the Grafana database before upgrading. Reverting the image doesn't undo database migrations.
