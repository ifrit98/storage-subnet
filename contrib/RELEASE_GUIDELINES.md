# Release Guidelines

The release manager in charge can release a FileTAO version using two scripts:
  - [./scripts/release/versioning.sh](./scripts/release/versioning.sh)
  - [./scripts/release/release.sh](./scripts/release/release.sh)

The release manager will need the right permissions for:
  - github.com
  - pypi.org

If you are new in this role, ask for the proper setup you need to run this process manually.

## Process of release

1. Create a branch called `release/VERSION`, having VERSION with the version to release.
1. Within the release branch:
  1. Update the version executing:`./scripts/release/versioning.sh --update UPDATE_TYPE`
    1. **UPDATE_TYPE** could be *major*, *minor* or *patch*.
  1. Add release notes to CHANGELOG executing: `./scripts/release/add_notes_changelog.sh -A -V NEW_VERSION -P PREVIOUS_TAG -T GH_ACCESS_TOKEN`
    1. **NEW_VERSION**: e.g.: 1.0.1
    1. **PREVIOUS_TAG**: e.g.: 1.0.0
    1. **GH_ACCESS_TOKEN**: A github [personal access token](https://docs.github.com/en/enterprise-server@3.4/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) you need. 

1. Test the release branch and verify that it meets the requirements.
1. After merging the release branch; Run the release script

## Versioning script usage

Options:
  - -U, --update: type of update. It could be major, minor, patch or rc (release candidate).
  - -A, --apply: This specify to apply the release. Without this the versioning will just show a dry run with no changes.

## Release script usage

Options:
  - -A, --apply: This specify to apply the release. Without this the release will just show a dry run with no changes.
  - -T,--github-token: A github personal access token to interact with the Github API.

### Github token

Since you need to use a secret when releasing FileTAO (github personal access token), I encourage you to use [pass](https://www.passwordstore.org/) or a similar tool that allows you to store the secret safely and not expose it in the history of the machine you use.

So you can have:
```
GITHUB_ACCESS_TOKEN=$(pass github/your_personal_token_with_permisions)
```

or
```
GITHUB_ACCESS_TOKEN=$(whatever you need to get the token safely)
```

### Executions

So, executing the script to release a minor version will be:

```
# For a dry run
./scripts/release/release.sh
```

```
# Applying changes
./scripts/release/release.sh --apply --github-token $GITHUB_ACCESS_TOKEN`
```

## Checking release

After the execution of the release script we would have generated:
  - A new git tag in [github.com](https://github.com/ifrit98/storage-subnet/tags)
  - A new github release in [github.com](https://github.com/ifrit98/storage-subnet/releases)
  - A new pip package in [pypi.org](https://pypi.org/project/filetao/#history)
  - A new docker image in [hub.docker.com](https://hub.docker.com/r/philanthrope/filetao/tags)

