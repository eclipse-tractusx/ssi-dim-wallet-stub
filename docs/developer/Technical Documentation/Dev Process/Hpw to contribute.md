# Contribution details

To contribute to the Policy Hub as part of the open source community, please read the details defined below.
Besides a generic "how to", some commit and pull request (PR) guidelines are defined to ensure readability and make
newly created PRs easier to review. Additionally, changelogs can get validated as well as written with more ease.
Moreover, similar patterns are in use across the contributor community.

**Content**:

- [Commit How To](#how-to-contribute)
- [Commits, branches and pull requests guidelines](#commits-branches-and-pull-requests-guidelines)

## How To Contribute

### 1 Create a fork

Open [GitHub - "eclipse-tractusx" project](https://github.com/eclipse-tractusx) and select the respective repository to
which you want to contribute.
[Create a fork of the respective repo](https://docs.github.com/en/get-started/quickstart/fork-a-repo).

### 2 Fork setup

Setup your fork by entering a name and make sure that you unselect the "main branch only" selection, in case the
upstream repository maintains release branches besides the main branch.

Click "Create fork".

### 3 Commit

With the newly created fork, you can now start to contribute. Create a new branch in your own fork and start to
implement the planned changes or new features.
When the implementation is ready, create a PR against the upstream repository.

The PR will get reviewed by the repository owners/official committers.
As part of the PR review, checks will run automatically, and unit tests (if configured) will get executed. The PR owner
is responsible to check the results and fix possible findings.

## Commits, branches and pull requests guidelines

### Commits and branches

The suggestion is to use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

Here are some examples:

#### Feature branch

```mermaid
%%{init: { 'logLevel': 'debug', 'theme': 'base' } }%%
gitGraph
    commit id: "chore: initial commit"
    branch feature/feature1 order: 2
    commit id:"feat(function): add feature1"
    commit id:"feat(function): enable feature1"
    checkout main
    merge feature/feature1
```

#### Bugfix branch

```mermaid
%%{init: { 'logLevel': 'debug', 'theme': 'base' } }%%
gitGraph
    commit id: "build(v0.1.0): merge in main"
    branch bug/bug1  order: 2
    commit id: "fix(function): change bug"
    checkout bug/bug1
    commit id:"fix(function): refactor bug"
    checkout main
    merge bug/bug1
```

#### Release branch

```mermaid
%%{init: { 'logLevel': 'debug', 'theme': 'base' } }%%
gitGraph
    commit id: "build(v0.1.0): merge in main"
    branch release/v1.0.0 order: 2
    commit id: "build(v1.0.0): bump version, changelog..." tag: "v1.0.0"
    checkout main
    merge release/v1.0.0
```

#### Hotfix branch

```mermaid
%%{init: { 'logLevel': 'debug', 'theme': 'base' } }%%
gitGraph
    commit id: "release: v1.0.0"
    branch release/v1.0.0 order: 2
    commit id: "build(v1.0.0): bump version, changelog..." tag: "v1.0.0"
    checkout main
    merge release/v1.0.0
    checkout release/v1.0.0
    branch hotfix/v1.0.1 order: 3
    checkout hotfix/v1.0.1
    commit id: "hotfix(v1.0.1): bump version, changelog..." tag: "v1.0.1"
```

### PR title

The suggested naming convention is '{type}{(function)}: {short summary}'.

### PR description

Add details to the change, fix or feature in the PR description.
What was changed, why was it changed (e.g. which issue was fixed or which requirement was implemented), and how was it
changed.

### Additional information

Please refer to the [Development Flow](./Dev-flow_git-diagram.md).

## NOTICE

This work is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

- SPDX-License-Identifier: Apache-2.0
- SPDX-FileCopyrightText: 2023 Contributors to the Eclipse Foundation
- Source URL: https://github.com/eclipse-tractusx/policy-hub
