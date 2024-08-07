# Dev flow (git diagram)

```mermaid
%%{init: { 'logLevel': 'debug', 'theme': 'base' } }%%
gitGraph
    commit id: "chore: initial commit"
    branch feature/feature1 order: 1
    checkout feature/feature1
    commit id:"feat(function): add feature1"
    checkout main
    merge feature/feature1
    branch feature/feature2 order: 3
    checkout feature/feature2
    commit id:"feat(function)!: WIP enable feature2"
    checkout main
    branch bug/bug1 order: 2
    commit id: "fix(function): change bug1"
    checkout main
    merge bug/bug1
    checkout feature/feature2
    commit id:"feat(function)!: finalize feature2"
    checkout main
    merge feature/feature2
    branch feature/feature3 order: 4
    commit id:"feat(function)!: WIP enable feature3"
    checkout main
    branch release/v1.0.0-rc.1 order: 5
    commit id: "build(v1.0.0-rc.1): bump version" tag: "v1.0.0-rc.1"
    checkout main
    merge release/v1.0.0-rc.1
    checkout release/v1.0.0-rc.1
    branch bug/bug2 order: 7
    checkout bug/bug2
    commit id: "fix(function): change bug2"
    checkout release/v1.0.0-rc.1
    branch release/v1.0.0-rc.2 order: 8
    checkout release/v1.0.0-rc.2
    merge bug/bug2
    commit id: "build(v1.0.0-rc.2): bump version" tag: "v1.0.0-rc.2"
    checkout main
    merge release/v1.0.0-rc.2
    checkout feature/feature3
    commit id:"feat(function)!: finalize feature3"
    checkout main
    merge feature/feature3
    checkout release/v1.0.0-rc.2
    branch release/v1.0.0 order: 8
    checkout release/v1.0.0
    commit id: "build(v1.0.0): bump version" tag: "v1.0.0"
    checkout main
    merge release/v1.0.0
    checkout release/v1.0.0
    branch hotfix/v1.0.1 order: 9
    checkout hotfix/v1.0.1
    branch bug/bug3 order: 10
    checkout bug/bug3
    commit id: "fix(function): change bug3"
    checkout hotfix/v1.0.1
    merge bug/bug3
    commit id: "build(v1.0.1): bump version" tag: "v1.0.1"
```

## NOTICE

This work is licensed under the [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0).

- SPDX-License-Identifier: Apache-2.0
- SPDX-FileCopyrightText: 2023 Contributors to the Eclipse Foundation
- Source URL: https://github.com/eclipse-tractusx/policy-hub
